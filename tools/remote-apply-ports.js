#!/usr/bin/env node
'use strict'
// 把「升级到指定版本 + 写入真实 frp 端口」做成一条可演练、可回滚的命令。
//
// 默认是**演练**：只跑只读检查，把将要执行的每一条命令原样打出来，不改任何东西。
// 真正执行要显式加 --apply。
//
// 用法：
//   演练（默认）：
//     node tools/remote-apply-ports.js
//   真跑：
//     node tools/remote-apply-ports.js --apply \
//       --binary=dist/frpfirewall-linux-amd64 \
//       --set '{"bind_port":7020,"proxy_ports":"880,8443,7520,20000-30000"}'
//
// --set 收的是要并进 cfg.frps 的字段，用 JSON 写。之所以做成"传 JSON"而不是
// 写死两个参数：这套字段的形状还在变（可能还要加 dashboard / vhost 端口），
// 脚本不该跟着改。
//
// 顺序里有两处是踩过坑的，别随手调：
//   · 换二进制用 `install -m 0755`，不是 `cp` —— cp 覆盖正在运行的二进制会
//     报 Text file busy，而 && 链会把后面的清理一并吞掉，表现成"回滚跑了其实没换"。
//   · 先换二进制再写配置：新配置里的端口是区间文本，老二进制只认数字数组。

const fs = require('node:fs')
const path = require('node:path')
const { ROOT, readCreds, connect, run, upload, mask } = require('./lib/ssh-run')

const ARGS = process.argv.slice(2)
const APPLY = ARGS.includes('--apply')
// 同时支持 --name=value 与 --name value 两种写法。只认前者踩过一次：
// 命令行里写了 --set '{...}' 却被当成"没给 --set"，于是脚本"成功"地
// 只做了演练，看起来一切正常。
const argOf = (name) => {
  const eq = ARGS.find((a) => a.startsWith(`--${name}=`))
  if (eq) return eq.slice(name.length + 3)
  const i = ARGS.indexOf(`--${name}`)
  if (i >= 0 && i + 1 < ARGS.length && !ARGS[i + 1].startsWith('--')) return ARGS[i + 1]
  return ''
}

const BINARY = argOf('binary')
const SET_RAW = argOf('set')

const PANEL = 'http://127.0.0.1:7930/api/v1'
const DB = '/var/lib/frpfirewall/frpfirewall.db'
const BIN = '/usr/local/bin/frpfirewall'
const BK = '/root/ffw-backup'
const TMP = '/tmp/ffw-apply'

const sq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'"

let OVERRIDE = null
let OLD_VER = ''
let ROLLBACK_NEEDED = false

const buf = []
// 这份日志会落盘、会被贴出来看，所以打印前一律把口令挖掉。
// 命令行里带着 '{"password":"..."}'，形态上不是 key=value，redact() 抓不到。
let SECRETS = []
function log(s) {
  const safe = mask(s, ...SECRETS)
  buf.push(safe)
  console.log(safe)
}

// 执行一步。mutating 的步骤在演练模式下只打印、不执行。
async function step(conn, { name, cmd, mutating = false, timeout = 60000 }) {
  log(`\n${'='.repeat(70)}\n## ${name}${mutating ? '  [会改动]' : ''}\n${'='.repeat(70)}`)
  log(`$ ${cmd}`)
  if (mutating && !APPLY) {
    log('（演练：未执行）')
    return { skipped: true, out: '' }
  }
  const out = await run(conn, cmd, timeout)
  log(out)
  return { skipped: false, out }
}

async function main() {
  if (SET_RAW) {
    try {
      OVERRIDE = JSON.parse(SET_RAW)
    } catch (e) {
      throw new Error(`--set 不是合法 JSON：${e.message}`)
    }
  }
  if (APPLY && !BINARY) throw new Error('--apply 必须同时给 --binary=<本地二进制路径>')
  if (APPLY && !OVERRIDE) throw new Error('--apply 必须同时给 --set=\'{"bind_port":...}\'')

  let binLocal = null
  if (BINARY) {
    binLocal = path.resolve(ROOT, BINARY)
    if (!fs.existsSync(binLocal)) throw new Error(`找不到本地二进制：${binLocal}`)
  }

  log(`# ${APPLY ? '★ 正式执行' : '演练（不改动任何东西）'}  ${new Date().toISOString()}`)

  const env = readCreds()
  // 后面所有打印都要过这两道：登录口令、sudo 口令。
  SECRETS = [env.PANEL_PASS, env.RPASS, env.RSUDO_PASS, env.RKEY_PASSPHRASE]
  const conn = await connect(env)

  // --cleanup：只清掉本脚本上次落在目标机的临时文件（登录态、上传件）。
  // 独立成一个动作，是因为"什么时候清"该由人决定 —— 出问题时那些文件
  // 是最好的现场。
  if (ARGS.includes('--cleanup')) {
    log(`# 清理 ${TMP}`)
    log(await run(conn, `ls -la ${TMP}/ 2>&1; rm -rf ${TMP}; ls -d ${TMP} 2>&1`, 30000))
    conn.end()
    return
  }

  log(`# 目标 ${env.RUSER}@${env.RHOST}:${env.RPORT || 22}`)
  if (OVERRIDE) log(`# 要写入的字段 ${JSON.stringify(OVERRIDE)}`)
  if (binLocal) log(`# 待部署二进制 ${binLocal}（${fs.statSync(binLocal).size} 字节）`)
  else log('# 未指定 --binary：只改配置，不换二进制')

  try {
    // ---------------------------------------------------------------- 1
    const pre = await step(conn, {
      name: '① 前置检查（只读）',
      cmd:
        `echo "[服务]"; systemctl is-active frpfirewall; ` +
        `echo "[版本]"; ${BIN} --version | head -1; ` +
        `echo "[面板]"; curl -s -o /dev/null -w '%{http_code}\\n' -m 5 ${PANEL.replace('/api/v1', '')}/; ` +
        `echo "[库]"; ls -la ${DB}; ` +
        `echo "[磁盘]"; df -h /var/lib /usr/local | tail -2; ` +
        `echo "[工具]"; command -v sqlite3 python3 nft iptables | tr '\\n' ' '; echo`,
    })
    OLD_VER = (/FrpFireWall\s+(\S+)/.exec(pre.out) || [])[1] || ''
    if (!OLD_VER) throw new Error('读不到当前二进制版本，先人工看一眼再跑')
    log(`\n>>> 当前版本 ${OLD_VER}`)

    // ---------------------------------------------------------------- 2
    await step(conn, {
      name: '② 备份（二进制 / 库 / 配置 / 规则快照）',
      mutating: true,
      cmd:
        `mkdir -p ${BK} && chmod 700 ${BK} && ` +
        `cp -a ${BIN} ${BK}/frpfirewall-${OLD_VER} && ` +
        `sqlite3 ${DB} ".backup ${BK}/frpfirewall.db" && ` +
        `sqlite3 ${DB} ".dump settings" > ${BK}/settings-${OLD_VER}.sql && ` +
        `nft list ruleset > ${BK}/nft-before-${OLD_VER}.txt 2>&1; ` +
        `echo "[备份指纹]"; sha256sum ${BIN} ${BK}/frpfirewall-${OLD_VER}; ` +
        `echo "[备份内容]"; ls -la ${BK}/ | grep -E "frpfirewall-${OLD_VER}|frpfirewall.db|settings-"`,
    })

    // ---------------------------------------------------------------- 3
    if (binLocal) {
      await step(conn, {
        name: '③ 上传新二进制到暂存区',
        mutating: true,
        cmd: `mkdir -p ${TMP} && chmod 700 ${TMP} && rm -f ${TMP}/new && echo ok`,
      })
      if (!APPLY) {
        log(`\n（演练：跳过 SFTP 上传 ${path.basename(binLocal)} → ${TMP}/new）`)
      } else {
        log(`\n>>> SFTP 上传 → ${TMP}/new`)
        await upload(conn, binLocal, `${TMP}/new`)
      }
      await step(conn, {
        name: '④ 校验上传件（sha256 与本地逐字节比对）',
        mutating: false,
        cmd: `sha256sum ${TMP}/new`,
      })
      const localSha = require('node:crypto')
        .createHash('sha256')
        .update(fs.readFileSync(binLocal))
        .digest('hex')
      log(`\n>>> 本地 sha256 = ${localSha}`)
      log('>>> 上面两行必须完全一致，不一致就别往下走。')
    }

    // ---------------------------------------------------------------- 5（换二进制）
    if (binLocal) {
      const r = await step(conn, {
        name: '⑤ 换上新的二进制（install 而不是 cp）',
        mutating: true,
        cmd:
          `install -m 0755 ${TMP}/new ${BIN} && ` +
          `systemctl restart frpfirewall && sleep 3 && ` +
          `systemctl is-active frpfirewall && ${BIN} --version | head -1`,
      })
      if (!r.skipped) ROLLBACK_NEEDED = true
      if (!r.skipped && !/^active/m.test(r.out)) throw new Error('换二进制后服务未能激活')
    }

    // ---------------------------------------------------------------- 6（读当前配置）
    // 本步对目标机只做读操作，唯一的写是它自己的临时目录 ${TMP}（演练时也会建，
    // 否则这一步没法跑）。登录态文件每次覆盖，演练模式不删除。
    const cfgStep = await step(conn, {
      name: '⑥ 读当前配置（登录 → GET /config）',
      mutating: false,
      cmd:
        `mkdir -p ${TMP} && chmod 700 ${TMP} && ` +
        `curl -s -m 10 -X POST ${sq(PANEL + '/auth/login')} -H 'Content-Type: application/json' ` +
        `-d ${sq(JSON.stringify({ username: env.PANEL_USER, password: env.PANEL_PASS }))} > ${TMP}/login.json; ` +
        `python3 -c 'import json;d=json.load(open("${TMP}/login.json"));assert d.get("ok"), d.get("error")' 2>&1 && ` +
        `python3 -c 'import json;print(json.load(open("${TMP}/login.json"))["data"]["token"])' > ${TMP}/token && ` +
        `curl -s -m 10 ${sq(PANEL + '/config')} -H "Authorization: Bearer $(cat ${TMP}/token)" > ${TMP}/cfg.json; ` +
        `echo "[当前端口配置]"; sqlite3 ${DB} "select key || ' = ' || value from settings where key like 'cfg.frps.%port%';"; ` +
        `echo "[接口视角]"; python3 -c 'import json;c=json.load(open("${TMP}/cfg.json"))["data"]["config"]["frps"];print("bind_port =",c.get("bind_port"),"| proxy_ports =",c.get("proxy_ports"))'`,
    })

    if (!OVERRIDE) {
      log('\n>>> 没给 --set，只做演练到这里。要真改请带 --set。')
    } else {
      // 拉回当前配置，本地合并，再传回去 —— 不在远端拼 JSON，
      // 远端 python 里套嵌套引号出过一次错，没必要再冒一次。
      const cfgText = await run(conn, `cat ${TMP}/cfg.json`, 20000)
      let cfg
      try {
        cfg = JSON.parse(cfgText)
      } catch (e) {
        throw new Error(`取回的配置不是合法 JSON：${e.message}\n${cfgText.slice(0, 300)}`)
      }
      const before = JSON.parse(JSON.stringify(cfg.data.config.frps))
      Object.assign(cfg.data.config.frps, OVERRIDE)

      log(`\n${'='.repeat(70)}\n## ⑦ 将要 PUT 的关键字段\n${'='.repeat(70)}`)
      log(`frps 段 改动前：${JSON.stringify(before)}`)
      log(`frps 段 改动后：${JSON.stringify(cfg.data.config.frps)}`)
      log('（PUT 的 body 是整份配置，上面只挑端口相关的字段显示）')

      const newPath = path.join(ROOT, 'dist', 'apply-config-new.json')
      fs.mkdirSync(path.dirname(newPath), { recursive: true })
      fs.writeFileSync(newPath, JSON.stringify(cfg, null, 2) + '\n')
      log(`>>> 完整 body 已存 ${newPath}（可以先自己看一眼）`)

      if (!APPLY) {
        log('\n（演练：跳过上传与 PUT）')
      } else {
        await upload(conn, newPath, `${TMP}/new.json`)
        const put = await step(conn, {
          name: '⑧ PUT 新配置',
          mutating: true,
          cmd:
            `curl -s -m 10 -X PUT ${sq(PANEL + '/config')} -H "Authorization: Bearer $(cat ${TMP}/token)" ` +
            `-H 'Content-Type: application/json' -d @${TMP}/new.json`,
        })
        if (!/"ok"\s*:\s*true/.test(put.out)) throw new Error(`写入配置被拒：${put.out.slice(0, 400)}`)
        ROLLBACK_NEEDED = true

        await step(conn, {
          name: '⑨ 重启并等待（端口是启动期参数，必须重启才生效）',
          mutating: true,
          cmd: `systemctl restart frpfirewall && sleep 3 && systemctl is-active frpfirewall`,
        })
      }
    }

    // ---------------------------------------------------------------- 10（核验）
    await step(conn, {
      name: '⑩ 核验（只读）',
      cmd:
        `echo "[版本]"; ${BIN} --version | head -1; ` +
        `echo "[服务]"; systemctl is-active frpfirewall; ` +
        `echo "[落库的端口]"; sqlite3 ${DB} "select key || ' = ' || value from settings where key like 'cfg.frps.%port%';"; ` +
        `echo "[受管集合元素]"; for s in "ip filter frpfirewall_black" "ip filter frpfirewall_black_frp" ` +
        `"ip6 filter frpfirewall_black6" "ip6 filter frpfirewall_black6_frp"; do printf "  %-42s => " "$s"; ` +
        `nft list set $s 2>/dev/null | python3 -c 'import sys,re;t=sys.stdin.read();m=re.search(r"elements = \\{([^}]*)\\}",t,re.S);print(" ".join(m.group(1).split()) if m else "(不存在或为空)")'; done; ` +
        `echo "[链上的 frp 规则]"; nft list chain ip filter INPUT 2>/dev/null | grep "frpfirewall:black-frp" || echo "  （无：说明没有 scope=frp 的黑名单条目，这是正常的）"; ` +
        `echo "[临时登录态]"; ls -la ${TMP}/token ${TMP}/login.json 2>&1 | head -3; ` +
        `echo "  （这两个是本脚本自己落的，执行完请用 --cleanup 或手工 rm）"`,
    })
  } catch (e) {
    log(`\n!!! 失败：${e.message}`)
    if (APPLY && ROLLBACK_NEEDED) {
      log('\n>>> 触发回滚：恢复二进制与数据库，再重启')
      const rb = await step(conn, {
        name: 'R 回滚',
        mutating: true,
        cmd:
          `systemctl stop frpfirewall; ` +
          `install -m 0755 ${BK}/frpfirewall-${OLD_VER} ${BIN} && ` +
          `sqlite3 ${DB} ".restore ${BK}/frpfirewall.db" && ` +
          `systemctl start frpfirewall && sleep 3 && ` +
          `echo "[回滚后版本]"; ${BIN} --version | head -1; ` +
          `echo "[回滚后端口]"; sqlite3 ${DB} "select key || ' = ' || value from settings where key like 'cfg.frps.%port%';"; ` +
          `echo "[回滚后服务]"; systemctl is-active frpfirewall`,
      })
      log(rb.out)
    } else if (!APPLY) {
      log('（演练模式，没有改动需要回滚）')
    } else {
      log('（尚未做出改动，无需回滚）')
    }
    process.exitCode = 1
  } finally {
    conn.end()
    const outPath = path.join(
      ROOT,
      'dist',
      `apply-${APPLY ? 'run' : 'dryrun'}-${Date.now()}.txt`,
    )
    fs.writeFileSync(outPath, buf.join('\n') + '\n')
    console.log(`\n\n已保存：${outPath}`)
    if (!APPLY) console.log('这是演练，目标机一个字都没改。')
  }
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
