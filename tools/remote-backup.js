#!/usr/bin/env node
'use strict'
// 备份与基线记录。
//
// 在动生产机之前，把「回得去」这件事做实：二进制、数据库、规则快照三样齐备，
// 并且记下当前状态作为后续对比的基线。这一步本身不改变任何东西。
//
// 用法：NODE_PATH=... node tools/remote-backup.js

const path = require('node:path')
const fs = require('node:fs')
const { ROOT, readCreds, connect, run } = require('./lib/ssh-run')

const BK = '/root/ffw-backup'
const DB = '/var/lib/frpfirewall/frpfirewall.db'

// 每组命令都要能安全重复执行（幂等），否则出问题时没法再跑一遍。
const STEPS = [
  {
    name: '① 建备份目录',
    cmd: `mkdir -p ${BK} && chmod 700 ${BK} && echo ok`,
  },
  {
    name: '② 备份现有二进制',
    cmd: `cp -a /usr/local/bin/frpfirewall ${BK}/frpfirewall-pre.05 && cp -a /usr/local/bin/frpfirewall-panic ${BK}/frpfirewall-panic 2>/dev/null; ls -la ${BK}/`,
  },
  {
    name: '③ 二进制指纹（回滚时的判据）',
    cmd: `sha256sum /usr/local/bin/frpfirewall ${BK}/frpfirewall-pre.05`,
  },
  {
    name: '④ 在线备份数据库（sqlite .backup，运行中安全）',
    cmd: `sqlite3 ${DB} ".backup ${BK}/frpfirewall.db" && ls -la ${BK}/frpfirewall.db && echo "--- 备份件能正常读取 ---" && sqlite3 ${BK}/frpfirewall.db "select (select count(*) from acl_entries) || ' acl / ' || (select count(*) from ban_records) || ' bans';"`,
  },
  {
    name: '⑤ 导出台账（可重放）',
    cmd: `sqlite3 ${DB} ".dump acl_entries" > ${BK}/acl_entries.sql; sqlite3 ${DB} ".dump ban_records" > ${BK}/ban_records.sql; wc -l ${BK}/acl_entries.sql ${BK}/ban_records.sql`,
  },
  {
    name: '⑥ 非敏感配置导出',
    cmd: `sqlite3 -header -column ${DB} "select key, value from settings where key not like '%password%' and key not in ('jwt_secret','setup_token') order by key;" | tee ${BK}/settings-nonsecret.txt`,
  },
  {
    name: '⑦ 规则快照',
    cmd: `iptables-save > ${BK}/iptables-save.txt 2>&1; ip6tables-save > ${BK}/ip6tables-save.txt 2>&1; nft list ruleset > ${BK}/nft-ruleset.txt 2>&1; wc -l ${BK}/iptables-save.txt ${BK}/ip6tables-save.txt ${BK}/nft-ruleset.txt`,
  },
  {
    name: '⑧ 基线：受管集合与元素',
    cmd: `echo "=== ip filter / frpfirewall_black ==="; nft list set ip filter frpfirewall_black 2>&1; echo "=== ip6 filter / frpfirewall_black6 ==="; nft list set ip6 filter frpfirewall_black6 2>&1; echo "=== 是否已有 frp 范围集合（预期没有）==="; nft list ruleset 2>/dev/null | grep -c "frpfirewall_black_frp" || true`,
  },
  {
    name: '⑨ 基线：受管规则在 INPUT 链中的位置',
    cmd: `echo "=== v4 INPUT（编号）==="; iptables -S INPUT | grep -n . | head -12; echo; echo "=== v6 INPUT（编号）==="; ip6tables -S INPUT | grep -n . | head -8`,
  },
  {
    name: '⑩ 基线：服务与数据版本',
    cmd: `systemctl is-active frpfirewall; systemctl show frpfirewall -p ActiveEnterTimestamp -p ExecMainPID; echo "--- 版本 ---"; /usr/local/bin/frpfirewall -version 2>&1 | head -3; echo "--- 表结构（是否已有 scope 列）---"; sqlite3 ${DB} "select name from pragma_table_info('acl_entries') where name='scope'; select name from pragma_table_info('ban_records') where name='scope';"`,
  },
  {
    name: '⑪ 旁证：frps 的真实位置与配置',
    cmd: `echo "=== frps 进程 ==="; ps -eo pid,etime,args | grep "[f]rps" | head -3; echo "=== 宿主是否能看到它的文件 ==="; ls -la /data/bin/frps /data/frps-1.json 2>&1 | head -4; echo "=== 进程根目录 ==="; ls -la /proc/1173986/root/data/ 2>&1 | head -12; echo "=== cgroup（判断是否容器）==="; head -2 /proc/1173986/cgroup 2>&1`,
  },
  {
    name: '⑫ 备份清单',
    cmd: `ls -la ${BK}/; echo "--- 总计 ---"; du -sh ${BK}/`,
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

  log(`# 备份与基线 ${new Date().toISOString()}`)
  log(`# 目标 ${env.RUSER}@${env.RHOST}:${env.RPORT || 22}`)
  log(`# 备份目录 ${BK}（不改动任何运行状态）\n`)

  for (const s of STEPS) {
    log(`\n${'='.repeat(66)}\n## ${s.name}\n${'='.repeat(66)}`)
    log(`$ ${s.cmd}`)
    log(await run(conn, s.cmd, 60000))
  }

  conn.end()

  const outDir = path.join(ROOT, 'dist')
  fs.mkdirSync(outDir, { recursive: true })
  const out = path.join(outDir, `remote-backup-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`\n\n已保存：${out}`)
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
