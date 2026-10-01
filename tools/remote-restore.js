'use strict'
// 把目标机还原成"正式发布版 + 明确的端口配置"。
//
// 场景：验证跑完之后，机器上留着测试构建（版本号里带自定义标记、不可追溯），
// 配置也被临时改过。生产机不该停在这种状态 —— 版本号一旦不是可追溯的构建，
// 出问题时就无法判断到底跑的是哪份代码。
//
// 顺序有讲究：先用**新版本**把配置写成目标形态（新版本认字符串写法），
// 再换二进制。反过来的话，老版本的接口只认数字数组，写配置那一步会失败。
//
// 用法：node tools/remote-restore.js <目标二进制> <bind_port> <proxy_ports>

const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const { readCreds, connect, run, upload } = require('./lib/ssh-run')

const BASE = 'http://127.0.0.1:7930/api/v1'
const TOKEN = '/tmp/ffw-token'
const REMOTE_BIN = '/usr/local/bin/frpfirewall'
const BACKUP_DIR = '/root/ffw-backup'

// 远端路径允许写成 root/ffw-backup/xxx（不带前导斜杠）。
//
// 原因：调用方通常跑在 Git Bash 里，而 MSYS 会把 /root/xxx 这种绝对路径就地改写成
// <Git 安装目录>/root/xxx —— 传进来就已经不是原来的字符串了（实测过）。
// 而 Windows 盘符路径不受影响，本地相对路径一般也还原得回来。所以判定规则是
// 「看起来还像本地路径就按本地处理，否则按远端补上前导斜杠」。
const rawArg = process.argv[2] || ''
const looksLocal =
  /^[A-Za-z]:[\\/]/.test(rawArg) || rawArg.startsWith('\\\\') || fs.existsSync(rawArg)
const isRemoteSrc = !looksLocal
const targetBin = isRemoteSrc ? '/' + rawArg.replace(/^\/+/, '') : path.resolve(rawArg)
const wantBind = Number(process.argv[3] || 7000)
const wantPorts = process.argv[4] || '80,443'

const sq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'"

let conn
const sh = (cmd, t) => run(conn, cmd, t)

async function waitHealthy() {
  for (let i = 0; i < 40; i++) {
    const code = await sh(
      `curl -s -m 3 --noproxy '*' -o /dev/null -w '%{http_code}' http://127.0.0.1:7930/`,
    )
    if (code.trim() === '200') return true
    await new Promise((r) => setTimeout(r, 1000))
  }
  return false
}

async function api(method, p, body) {
  const data = body === undefined ? '' : ` -d ${sq(JSON.stringify(body))}`
  return sh(
    `curl -s -m 20 -X ${method} ${sq(BASE + p)} ` +
      `-H "Authorization: Bearer $(cat ${TOKEN})" -H 'Content-Type: application/json'${data}`,
  )
}

;(async () => {
  // 参数可以给本地路径（会被上传），也可以给远端路径（直接就地使用）。
  // 用远端路径是为了能直接装回备份目录里那份与 Release 逐字节一致的官方二进制，
  // 而不是本地重新编译出来、版本号里带着本地 commit 的另一份。
  if (!rawArg) {
    throw new Error(
      '用法：node tools/remote-restore.js <本地路径|远端路径> [bind_port] [proxy_ports]\n' +
        '  本地：dist/frpfirewall-linux-amd64\n' +
        '  远端：root/ffw-backup/frpfirewall-pre.05（不要写前导斜杠，见文件顶部说明）',
    )
  }
  const env = readCreds()
  conn = await connect(env)

  console.log('===== 还原前 =====')
  console.log(`  ${await sh(`${REMOTE_BIN} --version`)}`)
  console.log(`  sha256: ${(await sh(`sha256sum ${REMOTE_BIN} | awk '{print $1}'`)).trim()}`)

  // 登录（接口带限流，只调一次）
  await sh(
    `curl -s -m 10 -X POST ${sq(BASE + '/auth/login')} -H 'Content-Type: application/json' ` +
      `-d ${sq(JSON.stringify({ username: env.PANEL_USER, password: env.PANEL_PASS }))} ` +
      `> /tmp/ffw-login.json && ` +
      `python3 -c 'import json;print(json.load(open("/tmp/ffw-login.json"))["data"]["token"])' > ${TOKEN} && ` +
      `rm -f /tmp/ffw-login.json`,
  )

  // 把当前这份（已验证过的）构建存进备份目录，以免被覆盖后找不回来。
  const stamp = (await sh('date +%Y%m%d-%H%M%S')).trim()
  const keepDir = `${BACKUP_DIR}/verified-${stamp}`
  await sh(
    `mkdir -p ${keepDir} && install -m 0755 ${REMOTE_BIN} ${keepDir}/frpfirewall.verified && ` +
      `install -m 0755 /var/lib/frpfirewall/frpfirewall.db ${keepDir}/frpfirewall.db`,
  )
  console.log(`  已把当前构建留档到 ${keepDir}/`)

  console.log('\n===== 写配置 =====')
  const cfgResp = JSON.parse(await api('GET', '/config'))
  const cfg = cfgResp.data.config
  console.log(`  改前: bind_port=${cfg.frps.bind_port} proxy_ports=${JSON.stringify(cfg.frps.proxy_ports)}`)
  cfg.frps.bind_port = wantBind
  cfg.frps.proxy_ports = wantPorts
  const tmp = path.join(os.tmpdir(), 'ffw-restore-cfg.json')
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2))
  await upload(conn, tmp, '/tmp/ffw-restore-cfg.json')
  const put = JSON.parse(
    await sh(
      `curl -s -m 20 -X PUT ${sq(BASE + '/config')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
        `-H 'Content-Type: application/json' -d @/tmp/ffw-restore-cfg.json`,
    ),
  )
  if (!put.ok) throw new Error(`写配置失败：${JSON.stringify(put).slice(0, 200)}`)
  console.log(`  改后: bind_port=${wantBind} proxy_ports=${wantPorts}`)

  console.log('\n===== 换回目标二进制 =====')
  let srcPath = targetBin
  if (isRemoteSrc) {
    if (!(await sh(`test -f ${sq(targetBin)} && echo yes`)).includes('yes')) {
      throw new Error(`远端找不到 ${targetBin}`)
    }
    console.log(`  来源（远端）: ${targetBin}`)
  } else {
    await upload(conn, targetBin, '/tmp/ffw-restore-bin')
    srcPath = '/tmp/ffw-restore-bin'
    console.log(`  来源（上传）: ${targetBin}`)
  }
  const sha = (await sh(`sha256sum ${srcPath} | awk '{print $1}'`)).trim()
  console.log(`  待装版本: ${await sh(`${srcPath} --version`)}`)
  console.log(`  sha256: ${sha}`)
  // install 会先 unlink 再创建；直接 cp 覆盖正在运行的文件会被内核回
  // "Text file busy"，而且失败会静默发生在 `&&` 链里 —— 看起来回滚跑了，其实没换。
  await sh(
    `install -m 0755 ${srcPath} ${REMOTE_BIN} && rm -f /tmp/ffw-restore-bin /tmp/ffw-restore-cfg.json ${TOKEN}`,
  )
  await sh('systemctl restart frpfirewall')
  if (!(await waitHealthy())) throw new Error('重启后 40 秒仍没起来')

  console.log('\n===== 还原后复核 =====')
  console.log(`  ${await sh(`${REMOTE_BIN} --version`)}`)
  console.log(`  sha256: ${(await sh(`sha256sum ${REMOTE_BIN} | awk '{print $1}'`)).trim()}`)
  console.log(`  服务: ${await sh('systemctl is-active frpfirewall')}`)
  console.log(
    await sh(
      `echo "--- nft 受管规则 ---"; nft list chain ip filter INPUT 2>/dev/null | grep frpfirewall; ` +
        `echo "--- 集合元素 ---"; ` +
        `nft list set ip filter frpfirewall_black | tr '\\n' ' ' | sed 's/  */ /g'; echo; ` +
        `nft list set ip filter frpfirewall_black_frp | tr '\\n' ' ' | sed 's/  */ /g'; echo`,
    ),
  )
  conn.end()
})().catch((e) => {
  console.error('失败：', e.message)
  if (conn) conn.end()
  process.exit(1)
})
