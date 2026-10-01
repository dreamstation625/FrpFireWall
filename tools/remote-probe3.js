#!/usr/bin/env node
'use strict'
// 第三轮只读侦察：配置内容。
//
// 前两轮确认了"装了什么、跑在哪"。这一轮看"配了什么" —— 尤其是 frp 端口集合。
// 本轮的 scope 功能要按 ProtectPorts 生成 dport，端口集合的规模直接决定
// nft 表达式与 iptables multiport 的规则条数，是这轮最需要实测的东西。
//
// 全程只读（sqlite3 只跑 SELECT）。用法：
//   NODE_PATH=... node tools/remote-probe3.js

const path = require('node:path')
const fs = require('node:fs')
const { ROOT, readCreds, connect, run, redact } = require('./lib/ssh-run')

const DB = '/var/lib/frpfirewall/frpfirewall.db'
const Q = (sql, opts) => `sqlite3 ${opts || '-header -column'} ${DB} "${sql}"`

const PROBES = [
  {
    title: '数据库表清单与关键表结构',
    why: '确认设置项落在哪张表、字段叫什么',
    cmds: [
      Q(".tables", ''),
      Q("select name from sqlite_master where type='table' order by name;", ''),
      `echo "=== settings 结构 ==="; ${Q('.schema settings')}`,
      `echo "=== acl_entries 结构 ==="; ${Q('.schema acl_entries')}`,
      `echo "=== ban_records 结构 ==="; ${Q('.schema ban_records')}`,
    ],
  },
  {
    title: '★ 关键设置（值脱敏）',
    why: '取后端类型、面板监听、frp 端口配置 —— frp 范围要按它生成 dport',
    cmds: [
      Q('select * from settings order by key;'),
      `echo "=== 表行数 ==="; ${Q(
        "select (select count(*) from acl_entries) as acl, (select count(*) from ban_records) as bans;"
      )}`,
    ],
  },
  {
    title: '名单与封禁内容',
    why: '确认这台机器上真实在用的数据规模；测试条目要能加入也能干净移除',
    cmds: [
      Q('select id,kind,target,target_type,source,remark from acl_entries order by id limit 30;'),
      Q('select id,target,source,scope_or_null,created_at from ban_records limit 5;', '-header -column'),
      `echo "=== ban_records 字段名 ==="; ${Q('select * from ban_records limit 1;')}`,
    ],
  },
  {
    title: 'frps 配置（凭据值已脱敏）',
    why: '取 bindPort 与代理端口 —— 这就是 frp 范围要封的端口',
    cmds: [
      'ls -la /data/frps-1.json /data/bin/frps 2>/dev/null',
      'echo "=== frps-1.json ==="; cat /data/frps-1.json',
      'echo "=== frps 进程的参数 ==="; ps -eo pid,args | grep "[f]rps" | head -3',
    ],
  },
  {
    title: '面板可达性与初始化状态',
    why: '后面要靠 API 下发测试条目；确认面板监听与是否已初始化',
    cmds: [
      `echo "=== 7930 监听 ==="; ss -lntp | grep 7930`,
      `echo "=== 本机自访（只看状态码）==="; curl -s -o /dev/null -w "panel=%{http_code}\\n" -m 5 http://127.0.0.1:7930/ ; curl -s -o /dev/null -w "health=%{http_code}\\n" -m 5 http://127.0.0.1:9100/frps/health`,
      `echo "=== 数据库里的用户表 ==="; ${Q('select id,username,created_at from users;')} 2>&1 | head -5`,
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

  log(`# 配置侦察 ${new Date().toISOString()}`)
  log(`# 目标 ${env.RUSER}@${env.RHOST}:${env.RPORT || 22}`)
  log('# 全程只读；疑似凭据的值已脱敏。\n')

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
  const out = path.join(outDir, `remote-probe3-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`\n\n已保存：${out}`)
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
