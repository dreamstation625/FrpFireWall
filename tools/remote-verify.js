#!/usr/bin/env node
'use strict'
// 通过面板 API 做只读核对。
//
// 密码走 .secrets/creds.env，不写进本文件；请求在目标机内部发往 127.0.0.1，
// 明文密码不出服务器。token 存到目标机的 0600 临时文件，避免出现在命令行里。
//
// 用法：NODE_PATH=... node tools/remote-verify.js

const path = require('node:path')
const fs = require('node:fs')
const { ROOT, readCreds, connect, run } = require('./lib/ssh-run')

const BASE = 'http://127.0.0.1:7930/api/v1'
const DB = '/var/lib/frpfirewall/frpfirewall.db'

// 用 python3 从 JSON 里挑字段，免得把整份配置（含长数组）糊满屏幕。
// 单引号包代码、代码内用双引号，这样嵌进 shell 最省心。
const PICK = `python3 -c 'import sys,json;d=json.load(sys.stdin);c=d["data"]["config"];print("backend          =",c["backend"]);print("listen           =",c["server"]["listen"]);print("bind_port        =",c["frps"]["bind_port"]);print("proxy_ports      =",c["frps"]["proxy_ports"]);print("trusted_proxies  =",c["frps"]["trusted_proxies"]);print("guard.enabled    =",c["guard"]["enabled"]);print("guard.dry_run    =",c["guard"]["dry_run"]);print("restart_required =",d["data"]["restart_required"])'`

async function main() {
  const env = readCreds()
  if (!env.PANEL_USER || !env.PANEL_PASS) {
    console.error('creds.env 里缺少 PANEL_USER / PANEL_PASS')
    process.exit(2)
  }
  const conn = await connect(env)
  const buf = []
  const log = (s) => {
    buf.push(s)
    console.log(s)
  }
  const step = async (title, cmd, timeout) => {
    log(`\n${'='.repeat(66)}\n## ${title}\n${'='.repeat(66)}`)
    const out = await run(conn, cmd, timeout || 30000)
    log(out)
    return out
  }

  log(`# API 只读核对 ${new Date().toISOString()}`)
  log(`# 目标 ${env.RUSER}@${env.RHOST}（API 经 127.0.0.1 调用）`)

  // ---- 登录 ----
  const loginRaw = await step(
    '① 登录',
    `curl -s -m 10 -X POST ${BASE}/auth/login -H 'Content-Type: application/json' ` +
      `-d '{"username":"${env.PANEL_USER}","password":"${env.PANEL_PASS}"}'`
  )
  let token = ''
  try {
    token = JSON.parse(loginRaw).data.token
  } catch {
    log('!! 登录响应无法解析，后续步骤跳过')
    conn.end()
    process.exit(1)
  }
  log(`token 长度 = ${token.length}`)
  await run(conn, `umask 077; printf '%s' '${token}' > /tmp/ffw-token; ls -l /tmp/ffw-token`)

  // URL 必须整体加引号：查询串里的 & 不加引号会被 shell 当成后台执行符，
  // 命令被拦腰截断，表现为 "bash: -H: command not found" 加一个 "未登录"。
  const api = (m, p, body) =>
    `curl -s -m 15 -X ${m} "${BASE}${p}" -H "Authorization: Bearer $(cat /tmp/ffw-token)" ` +
    `-H 'Content-Type: application/json' ${body ? `-d '${body}'` : ''}`

  // ---- 配置 ----
  await step('② 当前配置', `${api('GET', '/config')} | ${PICK} 2>&1`)

  // ---- 数据库 schema ----
  await step(
    '③ AutoMigrate 结果：scope 列与存量值',
    `echo "--- acl_entries schema ---"; sqlite3 ${DB} ".schema acl_entries"; ` +
      `echo "--- ban_records 是否有 scope 列（应为 1）---"; sqlite3 ${DB} "select count(*) from pragma_table_info('ban_records') where name='scope';"; ` +
      `echo "--- 存量 acl 行（scope 应为 all）---"; sqlite3 -header -column ${DB} "select id,kind,target,scope from acl_entries;"; ` +
      `echo "--- 存量 ban 行（scope 应为 all）---"; sqlite3 -header -column ${DB} "select id,target,scope,status from ban_records;"`
  )

  // ---- 名单 API ----
  await step('④ 名单接口返回值（应带 scope）', `${api('GET', '/acl/black?page=1&size=20')}`)

  // ---- 预览 ----
  await step('⑤ ★ 规则预览：当前数据（不下发）', `${api('POST', '/firewall/preview')}`, 60000)

  // ---- 受管规则 ----
  await step('⑥ 受管规则接口', `${api('GET', '/firewall/managed')}`)

  conn.end()

  const outDir = path.join(ROOT, 'dist')
  fs.mkdirSync(outDir, { recursive: true })
  const out = path.join(outDir, `remote-verify-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`\n\n已保存：${out}`)
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
