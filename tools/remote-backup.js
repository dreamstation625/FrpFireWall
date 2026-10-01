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

// 备份文件名里的版本标记从二进制自身读，别写死 —— 写死过一次：脚本里是
// frpfirewall-pre.05，换版本后仍然往这个名字上覆盖，回滚点时看到的是一个
// 骗人的文件名。命令行参数可覆盖：node tools/remote-backup.js my-tag
const TAG_ARG = process.argv[2] || ''

// 每组命令都要能安全重复执行（幂等），否则出问题时没法再跑一遍。
// 因为备份文件名要先知道当前版本才能定，所以这里做成按 tag 生成的函数。
function stepsFor(BACKUP_BIN) {
  return [
  {
    name: '① 建备份目录',
    cmd: `mkdir -p ${BK} && chmod 700 ${BK} && echo ok`,
  },
  {
    name: '② 把当前版本记进备份目录（回滚时确认「回到了哪一版」）',
    cmd: `/usr/local/bin/frpfirewall --version 2>&1 | head -1 | tee ${BK}/version-before.txt`,
  },
  {
    name: '③ 备份现有二进制',
    cmd: `cp -a /usr/local/bin/frpfirewall ${BACKUP_BIN} && cp -a /usr/local/bin/frpfirewall-panic ${BK}/frpfirewall-panic 2>/dev/null; ls -la ${BK}/`,
  },
  {
    name: '④ 二进制指纹（回滚时的判据）',
    cmd: `sha256sum /usr/local/bin/frpfirewall ${BACKUP_BIN}`,
  },
  {
    name: '⑤ 在线备份数据库（sqlite .backup，运行中安全）',
    cmd: `sqlite3 ${DB} ".backup ${BK}/frpfirewall.db" && ls -la ${BK}/frpfirewall.db && echo "--- 备份件能正常读取 ---" && sqlite3 ${BK}/frpfirewall.db "select (select count(*) from acl_entries) || ' acl / ' || (select count(*) from ban_records) || ' bans';"`,
  },
  {
    name: '⑥ 导出台账（可重放）',
    cmd: `sqlite3 ${DB} ".dump acl_entries" > ${BK}/acl_entries.sql; sqlite3 ${DB} ".dump ban_records" > ${BK}/ban_records.sql; wc -l ${BK}/acl_entries.sql ${BK}/ban_records.sql`,
  },
  {
    name: '⑦ 非敏感配置导出（含端口，回滚时要照它改回去）',
    cmd: `sqlite3 -header -column ${DB} "select key, value from settings where key not like '%password%' and key not in ('jwt_secret','setup_token') order by key;" | tee ${BK}/settings-nonsecret.txt`,
  },
  {
    name: '⑧ 规则快照',
    cmd: `iptables-save > ${BK}/iptables-save.txt 2>&1; ip6tables-save > ${BK}/ip6tables-save.txt 2>&1; nft list ruleset > ${BK}/nft-ruleset.txt 2>&1; wc -l ${BK}/iptables-save.txt ${BK}/ip6tables-save.txt ${BK}/nft-ruleset.txt`,
  },
  {
    name: '⑨ 基线：受管集合与元素',
    cmd: `for s in "ip filter frpfirewall_black" "ip filter frpfirewall_black_frp" "ip6 filter frpfirewall_black6" "ip6 filter frpfirewall_black6_frp"; do printf "%-44s => " "$s"; nft list set $s 2>/dev/null | python3 -c 'import sys,re;t=sys.stdin.read();m=re.search(r"elements = \\{([^}]*)\\}",t,re.S);print(" ".join(m.group(1).split()) if m else "(不存在或为空)")'; done; echo "--- 链上的 frp 规则 ---"; nft list chain ip filter INPUT 2>/dev/null | grep -c "frpfirewall:black-frp" || true`,
  },
  {
    name: '⑩ 基线：受管规则在 INPUT 链中的位置',
    cmd: `echo "=== v4 INPUT（编号）==="; iptables -S INPUT | grep -n . | head -12; echo; echo "=== v6 INPUT（编号）==="; ip6tables -S INPUT | grep -n . | head -8`,
  },
  {
    name: '⑪ 基线：服务与数据版本',
    cmd: `systemctl is-active frpfirewall; systemctl show frpfirewall -p ActiveEnterTimestamp -p ExecMainPID; echo "--- 版本 ---"; /usr/local/bin/frpfirewall --version 2>&1 | head -3; echo "--- 端口配置 ---"; sqlite3 ${DB} "select key || ' = ' || value from settings where key like '%port%';"; echo "--- 表结构（数据迁移已经跑过哪些列）---"; sqlite3 ${DB} "select 'acl.scope: ' || count(*) from pragma_table_info('acl_entries') where name='scope'; select 'ban.scope: ' || count(*) from pragma_table_info('ban_records') where name='scope';"`,
  },
  {
    name: '⑫ 旁证：frps 的真实位置与配置（容器内，只读；凭据已脱敏）',
    // frps 的配置里带明文 auth.token 与 webServer.password，绝不能原样落盘 ——
    // 备份日志是要留档、要贴出来看的东西。按 key 名把值换成占位符，
    // 保持 JSON 仍然合法（直接删行会让结构坏掉）。
    cmd:
      `echo "=== frps 进程 ==="; ps -eo pid,etime,args | grep "[f]rps" | head -3; ` +
      `echo "=== 进程监听的端口 ==="; PID=$(pgrep -f "[f]rps" | head -1); ` +
      `ss -lntp 2>/dev/null | grep "pid=$PID" | awk '{print $4}' | sort -u; ` +
      `echo "=== 容器内 frps 配置（token / password / secret 已打码）==="; ` +
      `sed -E 's/("(token|password|passwd|secret)"[[:space:]]*:[[:space:]]*)"[^"]*"/\\1"<REDACTED>"/Ig' ` +
      `/proc/$PID/root/data/frps-1.json 2>&1 | head -40`,
  },
  {
    name: '⑬ 备份清单',
    cmd: `ls -la ${BK}/; echo "--- 总计 ---"; du -sh ${BK}/`,
  },
  ]
}

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

  // 先问出当前版本，再决定备份文件名 —— 顺序不能反，否则只能写死。
  log(`${'='.repeat(66)}\n## ⓪ 读当前二进制版本\n${'='.repeat(66)}`)
  const verLine = (await run(conn, '/usr/local/bin/frpfirewall --version 2>&1 | head -1', 30000)).trim()
  log(`$ /usr/local/bin/frpfirewall --version\n${verLine}`)

  const ver = (/FrpFireWall\s+(\S+)/.exec(verLine) || [])[1]
  if (!ver) {
    conn.end()
    throw new Error(`认不出二进制版本（输出：${verLine}）；可以显式给一个 tag：node tools/remote-backup.js pre.05`)
  }
  const tag = TAG_ARG || ver
  const backupBin = `${BK}/frpfirewall-${tag}`
  log(`\n>>> 备份文件名：${backupBin}（版本 ${ver}${TAG_ARG ? '，tag 由命令行指定' : ''}）`)

  for (const s of stepsFor(backupBin)) {
    log(`\n${'='.repeat(66)}\n## ${s.name}\n${'='.repeat(66)}`)
    log(`$ ${s.cmd}`)
    log(await run(conn, s.cmd, 60000))
  }

  conn.end()

  const outDir = path.join(ROOT, 'dist')
  fs.mkdirSync(outDir, { recursive: true })
  const out = path.join(outDir, `remote-backup-${tag}-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`\n\n已保存：${out}`)
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
