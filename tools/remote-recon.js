#!/usr/bin/env node
// 远程 Linux 只读侦察：把"能不能安全地在这台机器上测防火墙"需要的信息一次捞回来。
//
// 全程只读 —— 不写文件、不改规则、不重启服务。判定和动手是分开的两步，
// 在跑过这个脚本之前，不要往目标机上发任何写操作。
//
// 用法：
//   set -a; . .secrets/creds.env; set +a
//   NODE_PATH=C:/Users/dream/.workbuddy/binaries/node/workspace/node_modules \
//     node tools/remote-recon.js
//
// 输出同时打印到终端并存进 dist/remote-recon-<时间戳>.txt。

'use strict'

const fs = require('node:fs')
const path = require('node:path')
const { Client } = require('ssh2')

const ROOT = path.resolve(__dirname, '..')
const OUT_DIR = path.join(ROOT, 'dist')

// 每一段命令都必须是幂等的只读操作。
// 分组是为了输出好读，顺便记录"为什么需要这条"。
const PROBES = [
  {
    title: '系统与内核',
    why: '确认发行版与内核版本，判断适用哪套后端',
    cmds: [
      'cat /etc/os-release 2>/dev/null | head -8',
      'uname -a',
      'id',
      'echo "uptime:$(uptime -p 2>/dev/null)"',
      'echo "mem:"; free -m 2>/dev/null | head -3',
      'echo "disk:"; df -h / 2>/dev/null | tail -1',
    ],
  },
  {
    title: '防火墙工具链',
    why: '决定 iptables 还是 nftables 后端；缺命令会导致探测失败',
    cmds: [
      'for c in iptables ip6tables iptables-save ip6tables-save nft ufw firewall-cmd; do printf "%-16s %s\\n" "$c" "$(command -v $c 2>/dev/null || echo -)"; done',
      'iptables --version 2>&1 | head -1',
      'nft --version 2>&1 | head -1',
      'echo "ufw: $(systemctl is-active ufw 2>/dev/null || echo -)"',
      'echo "firewalld: $(systemctl is-active firewalld 2>/dev/null || echo -)"',
      'echo "nftables.service: $(systemctl is-active nftables 2>/dev/null || echo -)"',
    ],
  },
  {
    title: '现有 INPUT 链结构（只读）',
    why: '关键：判断往链首插跳转会不会影响到正在跑的业务的报文路径',
    cmds: [
      'echo "=== iptables INPUT ==="; iptables -S INPUT 2>&1 | head -40',
      'echo "=== iptables 链一览 ==="; iptables -S 2>&1 | grep "^\\-N" | head -30',
      'echo "=== ip6tables INPUT ==="; ip6tables -S INPUT 2>&1 | head -20',
      'echo "=== nft base chain（含 policy，policy drop 要紧） ==="; nft -a list ruleset 2>&1 | grep -E "chain |policy |hook " | head -40',
      'echo "=== INPUT 上的 policy ==="; iptables -L INPUT -n 2>&1 | head -3',
    ],
  },
  {
    title: '监听端口与业务',
    why: '确认哪些端口在提供服务，测试时避开；也用来核对 frp 端口配置',
    cmds: [
      'ss -lntup 2>/dev/null | head -40',
      'echo "=== 已装的本程序 / frp ==="; command -v frpfirewall frps frpc 2>/dev/null || echo "(都没装)"',
      'systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk \'{print $1}\' | head -40',
    ],
  },
  {
    title: '受管规则残留检查',
    why: '确认本程序此前有没有在这台机器上跑过、有没有留下脏规则',
    cmds: [
      'echo "=== 本程序受管链 ==="; iptables -S 2>/dev/null | grep -i FRPFIREWALL || iptables -nL 2>/dev/null | grep -i FRPFIREWALL || echo "(无)"',
      'echo "=== 本程序受管集合/规则 ==="; nft list ruleset 2>/dev/null | grep -i frpfirewall || echo "(无)"',
      'echo "=== 本程序数据目录 ==="; ls -la /var/lib/frpfirewall 2>/dev/null || echo "(无)"',
    ],
  },
  {
    title: '救援手段可用性',
    why: '万一规则下发后 SSH 断了，要能确认带外通道是否还在',
    cmds: [
      'command -v iptables-save >/dev/null && echo "iptables-save: 可用（能把当前规则导出留档）" || echo "iptables-save: 缺失"',
      'echo "SSH 会话：$(who | wc -l) 个已登录会话"',
      'echo "SSH 端口：$(ss -lntp 2>/dev/null | grep -c sshd) 个 sshd 监听"',
    ],
  },
]

function readCreds() {
  const file = process.env.CREDS_FILE || path.join(ROOT, '.secrets/creds.env')
  if (!fs.existsSync(file)) {
    console.error(`找不到凭据文件：${file}`)
    console.error('先把 .secrets/creds.env 填上（RPASS 或 RKEY 二选一）。')
    process.exit(2)
  }
  const env = {}
  for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const i = line.indexOf('=')
    if (i <= 0) continue
    env[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  // 也允许用真实环境变量覆盖文件里的值
  for (const k of ['RHOST', 'RPORT', 'RUSER', 'RPASS', 'RKEY', 'RKEY_PASSPHRASE']) {
    if (process.env[k]) env[k] = process.env[k]
  }
  return env
}

function buildConfig(env) {
  const cfg = {
    host: env.RHOST,
    port: Number(env.RPORT || 22),
    username: env.RUSER,
    // 目标机若出现 host key 变化，脚本不该卡在交互提示上；
    // 这是测试机场景，指纹校验交给首次连接时人工确认。
    readyTimeout: 20000,
    keepaliveInterval: 10000,
  }
  if (env.RKEY) {
    cfg.privateKey = fs.readFileSync(env.RKEY)
    if (env.RKEY_PASSPHRASE) cfg.passphrase = env.RKEY_PASSPHRASE
  } else {
    cfg.password = env.RPASS
  }
  return cfg
}

function exec(conn, cmd) {
  return new Promise((resolve) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return resolve(`<执行失败: ${err.message}>`)
      let out = ''
      stream.on('data', (d) => (out += d))
      stream.stderr.on('data', (d) => (out += d))
      stream.on('close', () => resolve(out.trim() || '(无输出)'))
    })
  })
}

async function main() {
  const env = readCreds()
  if (!env.RHOST || !env.RUSER) {
    console.error('creds.env 里 RHOST / RUSER 还没填。')
    process.exit(2)
  }
  if (!env.RKEY && !env.RPASS) {
    console.error('creds.env 里 RKEY 和 RPASS 都没填，无法登录。')
    process.exit(2)
  }

  const conn = new Client()
  const buf = []
  const log = (s) => {
    buf.push(s)
    console.log(s)
  }

  log(`# 只读侦察 ${new Date().toISOString()}`)
  log(`# 目标 ${env.RUSER}@${env.RHOST}:${env.RPORT || 22}（认证：${env.RKEY ? '密钥' : '密码'}）`)
  log('# 本脚本不写任何文件、不改任何规则。\n')

  await new Promise((resolve, reject) => {
    conn
      .on('ready', resolve)
      .on('error', reject)
      .connect(buildConfig(env))
  }).catch((e) => {
    console.error(`连接失败：${e.message}`)
    if (/authentication/i.test(e.message)) console.error('认证失败 —— 核对 RUSER / RPASS。')
    process.exit(1)
  })

  for (const p of PROBES) {
    log(`\n${'='.repeat(64)}\n## ${p.title}\n## 为什么看这个：${p.why}\n${'='.repeat(64)}`)
    for (const c of p.cmds) {
      log(`\n$ ${c}`)
      log(await exec(conn, c))
    }
  }

  conn.end()

  fs.mkdirSync(OUT_DIR, { recursive: true })
  const out = path.join(OUT_DIR, `remote-recon-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`\n\n已保存：${out}`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
