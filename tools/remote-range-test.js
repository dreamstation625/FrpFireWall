'use strict'
// 端口区间表达的真机验证。
//
// 要证明的只有一件事：把 proxy_ports 填成 "20000-30000" 之后，落进内核的是
// **一条区间规则**，而不是把区间摊开成上万个端口 —— 后者在 iptables 侧会变成
// 上千条 multiport、在 nft 侧会变成一个上万元素的集合。
//
// 控风险的四条：
//   1. 测试地址用 RFC 5737 的 192.0.2.0/24，真实流量不可能来自那里
//   2. 动手前落备份，任一步失败立即回滚二进制与服务
//   3. 临时改的配置最后一定要改回去（改配置要重启，重启前先确认限速本来就是关的）
//   4. 收尾复核内核受管规则与基线一致
//
// 用法：node tools/remote-range-test.js [新二进制路径]

const path = require('node:path')
const fs = require('node:fs')
const { readCreds, connect, run, upload } = require('./lib/ssh-run')

const BASE = 'http://127.0.0.1:7930/api/v1'
const TOKEN = '/tmp/ffw-token'
const REMOTE_BIN = '/usr/local/bin/frpfirewall'
const BACKUP_DIR = '/root/ffw-backup'

// 测试用端口：故意选一个远离真实业务的区间，且刻意让 bind_port 落在区间之外，
// 这样能顺带验证"单端口 + 区间"的合并结果。
const TEST_BIND_PORT = 7020
const TEST_PROXY_PORTS = '20000-30000'
const TEST_ADDR = '192.0.2.5'

let passes = 0
let fails = 0
const log = (s) => console.log(s)

function record(name, ok, detail) {
  if (ok) {
    passes++
    log(`  PASS ${name}${detail ? '   ' + detail : ''}`)
  } else {
    fails++
    log(`  FAIL ${name}${detail ? '   ' + detail : ''}`)
  }
}

function sq(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'"
}

// 从 `nft list set` / `nft list chain` 的输出里取元素列表。
//
// 必须先压平空白再匹配：nft 在元素多时会按列宽折行，`elements = { ... }`
// 里的花括号会被换行拆开，直接正则匹配永远匹配不到（上一轮就栽在这，
// 表现成"集合不存在"这种完全错误的结论）。
function elementsOf(text) {
  const flat = String(text).replace(/\s+/g, ' ')
  const m = /elements = \{([^}]*)\}/.exec(flat)
  if (!m) return []
  return m[1]
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

// 把带 [LABEL] 标记的输出切成段。跨段裸匹配会出事：
// "frpfirewall:black" 是 "frpfirewall:black-frp" 的前缀，
// 不按段隔离就会把两类规则认成同一类。
function parseSections(text) {
  const out = {}
  let cur = '(head)'
  out[cur] = []
  for (const line of String(text).split('\n')) {
    const m = /^\[(.+?)\]$/.exec(line.trim())
    if (m) {
      cur = m[1]
      out[cur] = []
      continue
    }
    out[cur].push(line)
  }
  return out
}

let conn

async function sh(cmd, timeout) {
  return run(conn, cmd, timeout)
}

async function api(method, p, body) {
  const data = body === undefined ? '' : ` -d ${sq(JSON.stringify(body))}`
  return sh(
    `curl -s -m 20 -X ${method} ${sq(BASE + p)} ` +
      `-H "Authorization: Bearer $(cat ${TOKEN})" -H 'Content-Type: application/json'${data}`,
  )
}

// 服务重启后要等它真的回来再往下走，否则后面的断言全都会打在空气上。
async function waitHealthy(label) {
  for (let i = 0; i < 40; i++) {
    const code = await sh(
      `curl -s -m 3 --noproxy '*' -o /dev/null -w '%{http_code}' http://127.0.0.1:7930/`,
    )
    if (code.trim() === '200') return true
    await new Promise((r) => setTimeout(r, 1000))
  }
  log(`  !! ${label}：等 40 秒仍未就绪`)
  return false
}

async function restart() {
  await sh('systemctl restart frpfirewall')
  return waitHealthy('重启')
}

// 规则下发是异步的：Refresh 只重载内存，tickLoop 收到信号后还要等 150ms 防抖
// 才真正 Reconcile。刚加完条目就去看内核，看到的一定是上一轮的状态。
async function settle(ms) {
  await new Promise((r) => setTimeout(r, ms || 2500))
}

;(async () => {
  const localBin = path.resolve(process.argv[2] || 'dist/frpfirewall-linux-amd64-ports')
  const env = readCreds()
  conn = await connect(env)

  let originalBinSHA = ''
  let originalConfig = null
  let originalCfgJSON = ''
  let dir = ''
  let deployed = false
  let configChanged = false

  try {
    // ─────────────────────────── 基线 ───────────────────────────
    log('===== 1. 基线（只读）=====')
    originalBinSHA = (await sh(`sha256sum ${REMOTE_BIN} | awk '{print $1}'`)).trim()
    log(`  现有二进制 sha256: ${originalBinSHA}`)
    log(`  ${await sh(`${REMOTE_BIN} --version | head -2`)}`)

    // 登录接口带限流，连续调两次会被拦下，所以只调一次、落到远端文件再解析。
    const loginBody = sq(
      JSON.stringify({ username: env.PANEL_USER, password: env.PANEL_PASS }),
    )
    await sh(
      `curl -s -m 10 -X POST ${sq(BASE + '/auth/login')} -H 'Content-Type: application/json' ` +
        `-d ${loginBody} > /tmp/ffw-login.json`,
    )
    const loginOK = (
      await sh(
        `python3 -c 'import json;print(json.load(open("/tmp/ffw-login.json")).get("ok"))'`,
      )
    ).trim()
    if (loginOK !== 'True') {
      // 不回显响应体：里面带着 token。
      throw new Error('面板登录失败（请确认 .secrets/creds.env 里的 PANEL_USER / PANEL_PASS）')
    }
    await sh(
      `python3 -c 'import json;print(json.load(open("/tmp/ffw-login.json"))["data"]["token"])' > ${TOKEN}; ` +
        `rm -f /tmp/ffw-login.json`,
    )
    log(`  面板 token 已写入 ${TOKEN}（${(await sh(`wc -c < ${TOKEN}`)).trim()} 字节）`)

    originalConfig = JSON.parse(await api('GET', '/config'))
    // 深拷贝一份原配置留底。后面要就地改 frps 再写回去，如果拿的是同一个对象引用，
    // "原配置"会跟着一起被改掉，收尾时"恢复原配置"就会把测试值当成原值写回去 ——
    // 而且因为比较的两边都变了，那句断言还会显示 PASS。踩过，记在这里。
    originalCfgJSON = JSON.stringify(originalConfig.data.config)
    const frps = JSON.parse(originalCfgJSON).frps
    log(`  当前 bind_port=${frps.bind_port}  proxy_ports=${JSON.stringify(frps.proxy_ports)}`)
    log(`  当前 restart_required=${originalConfig.data.restart_required}`)

    const policy = JSON.parse(await api('GET', '/policy'))
    log(
      `  限速策略：enabled=${policy.data.rate_limit_enabled} per_sec=${policy.data.rate_limit_per_sec}`,
    )
    if (policy.data.rate_limit_enabled) {
      throw new Error(
        '目标机当前开着连接速率限制，临时改端口会真的影响线上流量，先停下来问用户',
      )
    }

    const baselineBlack = await sh(`nft list set ip filter frpfirewall_black`)
    log(`  基线全端口集合: ${baselineBlack.replace(/\s+/g, ' ').slice(0, 160)}`)
    const baselineElems = elementsOf(baselineBlack)

    // ─────────────────────────── 备份 ───────────────────────────
    log('\n===== 2. 备份 =====')
    const stamp = (await sh('date +%Y%m%d-%H%M%S')).trim()
    dir = `${BACKUP_DIR}/${stamp}`
    log(
      await sh(
        `mkdir -p ${dir} && cp -a ${REMOTE_BIN} ${dir}/frpfirewall.orig && ` +
          `cp -a /var/lib/frpfirewall/frpfirewall.db ${dir}/frpfirewall.db && ` +
          `iptables-save > ${dir}/iptables.rules 2>/dev/null; ` +
          `ip6tables-save > ${dir}/ip6tables.rules 2>/dev/null; ` +
          `nft list ruleset > ${dir}/nft.rules 2>/dev/null; ` +
          `ls -la ${dir}`,
      ),
    )

    // ─────────────────────────── 部署 ───────────────────────────
    log('\n===== 3. 部署新构建 =====')
    if (!fs.existsSync(localBin)) throw new Error(`找不到本地二进制：${localBin}`)
    const localSHA = require('node:crypto')
      .createHash('sha256')
      .update(fs.readFileSync(localBin))
      .digest('hex')
    log(`  本地 sha256: ${localSHA}`)
    await upload(conn, localBin, '/tmp/ffw-new')
    const remoteSHA = (await sh(`sha256sum /tmp/ffw-new | awk '{print $1}'`)).trim()
    record('上传文件校验一致', remoteSHA === localSHA, remoteSHA.slice(0, 16))

    deployed = true
    await sh(`install -m 0755 /tmp/ffw-new ${REMOTE_BIN} && rm -f /tmp/ffw-new`)
    await restart()
    log(`  ${await sh(`${REMOTE_BIN} --version | head -2`)}`)
    record(
      '新版已接管',
      (await sh(`${REMOTE_BIN} --version`)).includes('ports-'),
      '版本标记含 ports-',
    )

    // ─────────────────── 临时把端口改成区间 ───────────────────
    log('\n===== 4. 把 proxy_ports 改成区间（临时）=====')
    const cfg = JSON.parse(originalCfgJSON)
    cfg.frps.bind_port = TEST_BIND_PORT
    cfg.frps.proxy_ports = TEST_PROXY_PORTS
    const tmpLocal = path.join(require('node:os').tmpdir(), 'ffw-cfg-range.json')
    fs.writeFileSync(tmpLocal, JSON.stringify(cfg, null, 2))
    await upload(conn, tmpLocal, '/tmp/ffw-cfg-range.json')

    const put = JSON.parse(
      await sh(
        `curl -s -m 20 -X PUT ${sq(BASE + '/config')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
          `-H 'Content-Type: application/json' -d @/tmp/ffw-cfg-range.json`,
      ),
    )
    if (!put.ok) throw new Error(`写入配置失败：${JSON.stringify(put).slice(0, 200)}`)
    configChanged = true

    const stored = JSON.parse(await api('GET', '/config')).data.config.frps
    record(
      '区间原样落库',
      stored.proxy_ports === TEST_PROXY_PORTS,
      `proxy_ports=${stored.proxy_ports}`,
    )

    await restart()
    log(
      `  运行中的受保护端口: ` +
        (await sh(
          `curl -s -m 10 ${sq(BASE + '/system/info')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
            `| python3 -c 'import sys,json;d=json.load(sys.stdin)["data"];print("bind_port",d["bind_port"],"proxy_ports",d["proxy_ports"])'`,
        )),
    )

    // ─────────────────── 加一条 frp 范围的黑名单 ───────────────────
    log('\n===== 5. 加一条「仅 frp 端口」的黑名单（测试地址）=====')
    const add = JSON.parse(
      await api('POST', '/acl/black', {
        target: TEST_ADDR,
        scope: 'frp',
        remark: '区间验证用',
      }),
    )
    if (!add.ok) throw new Error(`加黑名单失败：${JSON.stringify(add).slice(0, 200)}`)
    log(`  已加 ${TEST_ADDR}，scope=${add.data?.scope}`)
    await settle()

    // ─────────────────────── 内核实况 ───────────────────────
    log('\n===== 6. 内核实况 =====')
    const dump = await sh(
      `for t in "ip filter" "ip6 filter"; do ` +
        `echo "[CHAIN $t]"; nft list chain $t INPUT | grep "frpfirewall:black" ; done; ` +
        `echo "[SETBLACK]"; nft list set ip filter frpfirewall_black; ` +
        `echo "[SETFRP]"; nft list set ip filter frpfirewall_black_frp; ` +
        `echo "[SETFRP6]"; nft list set ip6 filter frpfirewall_black6_frp`,
      60000,
    )
    log(dump)

    const sec = parseSections(dump)
    const v4rules = (sec['CHAIN ip filter'] || []).join('\n')
    const v6rules = (sec['CHAIN ip6 filter'] || []).join('\n')
    // 断言一律用"去掉所有空白"的形式：nft 打印集合元素是 `{ a, b }`，
    // 而脚本里手写的字符串很容易少一个空格 —— 那会变成假失败。
    const squash = (s) => s.replace(/\s+/g, '')
    const DPORT = `{${TEST_BIND_PORT},${TEST_PROXY_PORTS}}`

    record('v4 链上出现「仅 frp 端口」规则', /comment "frpfirewall:black-frp"/.test(v4rules))
    record(
      `v4 规则里是区间 ${DPORT}`,
      squash(v4rules).includes(`dport${DPORT}`),
      squash(v4rules).includes(`dport${DPORT}`)
        ? ''
        : '实际：' + v4rules.replace(/\n/g, ' | ').slice(0, 300),
    )
    record(
      '同一区间在 tcp 与 udp 上都有',
      squash(v4rules).includes(`tcpdport${DPORT}`) && squash(v4rules).includes(`udpdport${DPORT}`),
    )
    // 反向断言：区间一旦被展开，ruleset 里就会出现区间内部的值。
    record('区间没有被展开成逐个端口', !/\b20001\b/.test(dump) && !/\b29999\b/.test(dump))

    // nft 显示单个主机地址时会把 /32 去掉（写入的是 192.0.2.5/32，读回来是 192.0.2.5），
    // 所以比较前先把掩码剥掉，否则会变成一条永远失败的假断言。
    const hostOf = (s) => String(s).split('/')[0]
    const frpElems = elementsOf(sec['SETFRP'] || '')
    record(
      'frp 集合里只有测试地址',
      frpElems.length === 1 && hostOf(frpElems[0]) === TEST_ADDR,
      JSON.stringify(frpElems),
    )

    // 规则条数要克制：v4 上一个地址、tcp+udp 两条，不该多出成百上千条。
    const frpRuleCount = v4rules
      .split('\n')
      .filter((l) => l.includes('frpfirewall:black-frp')).length
    record('v4 上 frp 规则条数合理', frpRuleCount === 2, `${frpRuleCount} 条`)
    // 测试地址只有 v4，ip6 链上就不该出现 frp 规则 ——
    // 生成一条匹配空集合的规则看着无害，实际是把"没配"伪装成"配了"。
    record('ip6 链上没有多余的 frp 规则', !v6rules.includes('frpfirewall:black-frp'))

    // 受管规则报数（接口视角）
    const managed = await sh(
      `curl -s -m 15 ${sq(BASE + '/firewall/managed')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
        `| python3 -c 'import sys,json;[print(" ",s) for s in json.load(sys.stdin)["data"]["summary"]]'`,
    )
    log('  受管规则报数：\n' + managed)

    // ─────────────────────────── 清理 ───────────────────────────
    log('\n===== 7. 清理 =====')
    const del = await sh(
      `curl -s -m 15 ${sq(BASE + '/acl/black?page=1&size=50&keyword=' + TEST_ADDR)} ` +
        `-H "Authorization: Bearer $(cat ${TOKEN})" | python3 -c 'import sys,json;` +
        `items=json.load(sys.stdin)["data"]["items"];print(" ".join(str(i["id"]) for i in items))'`,
    )
    for (const id of del.trim().split(/\s+/).filter(Boolean)) {
      await api('DELETE', `/acl/black/${id}`)
      log(`  已删除黑名单条目 #${id}`)
    }
    await settle()

    // 恢复原配置（用留底的那份，不是被改过的对象）
    fs.writeFileSync(tmpLocal, JSON.stringify(JSON.parse(originalCfgJSON), null, 2))
    await upload(conn, tmpLocal, '/tmp/ffw-cfg-restore.json')
    const restored = JSON.parse(
      await sh(
        `curl -s -m 20 -X PUT ${sq(BASE + '/config')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
          `-H 'Content-Type: application/json' -d @/tmp/ffw-cfg-restore.json`,
      ),
    )
    if (!restored.ok) throw new Error(`恢复配置失败：${JSON.stringify(restored).slice(0, 200)}`)
    configChanged = false

    const backFrps = JSON.parse(await api('GET', '/config')).data.config.frps
    record(
      '配置已还原',
      backFrps.bind_port === frps.bind_port &&
        JSON.stringify(backFrps.proxy_ports) === JSON.stringify(frps.proxy_ports),
      `bind_port=${backFrps.bind_port} proxy_ports=${JSON.stringify(backFrps.proxy_ports)}`,
    )

    // 恢复原二进制。
    // 必须用 install 而不是 cp：目标文件正在被运行，cp 会以写方式打开它，
    // 内核直接回 "Text file busy"，而 `&&` 链会把后面的清理一并吞掉 ——
    // 表现成"回滚看起来跑了、其实文件没换"。install 先 unlink 再创建，没这个问题。
    await sh(
      `install -m 0755 ${dir}/frpfirewall.orig ${REMOTE_BIN} && ` +
        `rm -f /tmp/ffw-cfg-range.json /tmp/ffw-cfg-restore.json /tmp/ffw-token`,
    )
    deployed = false
    await restart()
    const finalSHA = (await sh(`sha256sum ${REMOTE_BIN} | awk '{print $1}'`)).trim()
    record(
      '二进制已回滚到原版本',
      finalSHA === originalBinSHA,
      finalSHA === originalBinSHA ? '' : `实际 ${finalSHA.slice(0, 16)} 期望 ${originalBinSHA.slice(0, 16)}`,
    )

    // ─────────────────────── 复核 ───────────────────────
    log('\n===== 8. 收尾复核（应回到基线）=====')
    const after = await sh(
      `echo "[SETBLACK]"; nft list set ip filter frpfirewall_black; ` +
        `echo "[SETFRP]"; nft list set ip filter frpfirewall_black_frp; ` +
        `echo "[INPUTRULES]"; nft list chain ip filter INPUT 2>/dev/null | grep -c "frpfirewall"; ` +
        `echo "[SERVICE]"; systemctl is-active frpfirewall`,
      60000,
    )
    log(after)

    const sec2 = parseSections(after)
    const afterElems = elementsOf(sec2['SETBLACK'] || '')
    record(
      '全端口集合与基线一致',
      JSON.stringify(afterElems) === JSON.stringify(baselineElems),
      JSON.stringify(afterElems),
    )
    record('frp 集合已清空', elementsOf(sec2['SETFRP'] || '').length === 0)
    record('服务在运行', /^active/m.test((sec2['SERVICE'] || []).join('\n')))
  } catch (e) {
    log(`\n!! 中断：${e.message}`)
    fails++
    // 失败也要把现场收回来
    try {
      log('  正在回滚…')
      if (configChanged && originalCfgJSON) {
        const tmp = path.join(require('node:os').tmpdir(), 'ffw-cfg-rollback.json')
        fs.writeFileSync(tmp, JSON.stringify(JSON.parse(originalCfgJSON), null, 2))
        await upload(conn, tmp, '/tmp/ffw-cfg-rollback.json')
        await sh(
          `curl -s -m 20 -X PUT ${sq(BASE + '/config')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
            `-H 'Content-Type: application/json' -d @/tmp/ffw-cfg-rollback.json > /dev/null; ` +
            `rm -f /tmp/ffw-cfg-rollback.json`,
        )
        log('  配置已回滚')
      }
      if (deployed && dir) {
        // 同上：正在运行的文件只能用 install 换，cp 会 Text file busy。
        await sh(`install -m 0755 ${dir}/frpfirewall.orig ${REMOTE_BIN}`)
        log('  二进制已回滚')
      }
      await sh('systemctl restart frpfirewall')
      await waitHealthy('回滚后重启')
      log('  服务已恢复')
    } catch (e2) {
      log(`  !! 回滚也失败了，需要人工介入：${e2.message}`)
    }
  } finally {
    log(`\n=======================================================`)
    log(`通过 ${passes} 项，失败 ${fails} 项`)
    log(fails === 0 ? '全部通过' : '存在失败项')
    conn.end()
    process.exit(fails === 0 ? 0 : 1)
  }
})()
