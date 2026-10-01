#!/usr/bin/env node
'use strict'
// 第二轮只读侦察：这台机器上 FrpFireWall 的部署现状。
//
// 第一轮已经确认「装好了、在跑、有规则生效」。这一轮要把它周围的细节补齐，
// 尤其是日志里那条悬而未决的问题 —— INPUT 链到底是 inet 单链还是 ip/ip6 双链。
// 这决定了新的 frp 范围集合该落在哪张表。
//
// 全程只读。用法：
//   NODE_PATH=... node tools/remote-probe2.js

const path = require('node:path')
const fs = require('node:fs')
const { ROOT, readCreds, connect, run, redact } = require('./lib/ssh-run')

const PROBES = [
  {
    title: '★ nftables 表结构（回答悬而未决的问题）',
    why: '决定 INPUT 是 inet 单链还是 ip/ip6 双链 —— frp 范围集合要落在这张表里',
    cmds: [
      'nft list tables',
      'echo "=== 每个表里的 base chain ==="; nft list ruleset | grep -E "^table|type filter hook"',
      'echo "=== frpfirewall 集合定义与元素 ==="; nft list ruleset | grep -A 6 "set frpfirewall"',
      'echo "=== 含 frpfirewall 的规则 ==="; nft list ruleset | grep "frpfirewall"',
    ],
  },
  {
    title: '★ 二进制版本',
    why: '判断这台机器上是哪个版本；决定本轮要不要替换二进制',
    cmds: [
      'ls -la /usr/local/bin/frpfirewall*',
      'sha256sum /usr/local/bin/frpfirewall',
      'echo "=== 版本字符串 ==="; grep -aoE "0\\.0\\.1-pre\\.[0-9]+" /usr/local/bin/frpfirewall | sort -u',
      'echo "=== 特征串对照（pre.05 修复标记）==="; for s in "两族各需一条 INPUT 链" "当前没有可用的" "规则语法预检失败"; do printf "%-24s %s\\n" "$s" "$(grep -ac "$s" /usr/local/bin/frpfirewall)"; done',
    ],
  },
  {
    title: '服务定义与运行参数',
    why: '弄清数据目录、监听参数、重启影响面',
    cmds: [
      'systemctl cat frpfirewall 2>&1 | head -40',
      'systemctl show frpfirewall -p ActiveEnterTimestamp -p ExecMainStartTimestamp -p FragmentPath -p Environment 2>&1',
      'echo "=== 进程详情 ==="; ps -eo pid,etime,args | grep -E "frpfirewall|frps " | grep -v grep',
      'echo "=== drop-in 覆盖 ==="; ls -la /etc/systemd/system/frpfirewall.service.d/ 2>/dev/null && cat /etc/systemd/system/frpfirewall.service.d/*.conf 2>/dev/null',
    ],
  },
  {
    title: '配置文件与数据目录',
    why: '确认设置项落在哪、有没有非默认值',
    cmds: [
      'find /etc -maxdepth 3 -iname "*frpfirewall*" 2>/dev/null',
      'ls -la /var/lib/frpfirewall/ 2>/dev/null',
      'echo "=== 可用的读库工具 ==="; command -v sqlite3 python3 2>/dev/null || echo "(都没有)"',
      'echo "=== 看是否有独立配置文件 ==="; for f in /etc/frpfirewall/* /var/lib/frpfirewall/*.yaml /var/lib/frpfirewall/*.json /var/lib/frpfirewall/*.toml; do [ -f "$f" ] && echo "--- $f ---" && head -40 "$f"; done 2>/dev/null || echo "(无)"',
    ],
  },
  {
    title: 'frps 现状（值已脱敏）',
    why: '取 bindPort 与代理端口 —— 这就是 frp 范围要封的端口集合',
    cmds: [
      'systemctl cat frps 2>&1 | head -25',
      'ls -la /etc/frp/ 2>/dev/null',
      'for f in /etc/frp/frps.toml /etc/frp/frps.ini /etc/frp/frps_full.ini; do [ -f "$f" ] && echo "--- $f ---" && cat "$f"; done 2>/dev/null',
      'ls -la /usr/local/bin/frps /usr/bin/frps 2>/dev/null; /usr/local/bin/frps --version 2>&1 | head -2',
    ],
  },
  {
    title: '共存的其它防火墙组件',
    why: 'INPUT policy 已是 DROP，还有 ufw / YJ / fail2ban 在写规则 —— 任何改动都要避开它们',
    cmds: [
      'echo "=== ufw ==="; ufw status verbose 2>&1 | head -30',
      'echo "=== fail2ban ==="; fail2ban-client status 2>&1 | head -8',
      'echo "=== 含 frpfirewall / YJ 的 iptables 规则 ==="; iptables -S | grep -iE "frpfirewall|YJ" | head -20',
      'echo "=== ipset 一览 ==="; ipset list -n 2>/dev/null | head -20 || echo "(无 ipset)"',
    ],
  },
]

async function main() {
  const env = readCreds()
  const conn = await connect(env)
  const buf = []
  const log = (s) => {
    buf.push(s)
    console.log(s)
  }

  log(`# 部署现状侦察 ${new Date().toISOString()}`)
  log(`# 目标 ${env.RUSER}@${env.RHOST}:${env.RPORT || 22}（认证：${env.RKEY ? '密钥' : '密码'}）`)
  log('# 全程只读。所有疑似凭据的值已脱敏。\n')

  for (const p of PROBES) {
    log(`\n${'='.repeat(66)}\n## ${p.title}\n## ${p.why}\n${'='.repeat(66)}`)
    for (const c of p.cmds) {
      log(`\n$ ${c}`)
      log(redact(await run(conn, c)))
    }
  }

  conn.end()

  const outDir = path.join(ROOT, 'dist')
  fs.mkdirSync(outDir, { recursive: true })
  const out = path.join(outDir, `remote-probe2-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`\n\n已保存：${out}`)
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
