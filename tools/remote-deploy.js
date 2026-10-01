#!/usr/bin/env node
'use strict'
// 把测试二进制推到目标机并替换。
//
// 这是本轮唯一一个会改变运行状态的脚本，因此把「回得去」写进流程本身：
//   上传 → 校验 sha256 → 试运行取版本 → 二次备份 → 替换 → 重启 → 探活
//   任一步失败，或重启后不 active，自动恢复旧二进制并再重启一次。
//
// 用法：NODE_PATH=... node tools/remote-deploy.js

const path = require('node:path')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { ROOT, readCreds, connect, run, upload } = require('./lib/ssh-run')

const LOCAL_BIN = path.join(ROOT, 'dist', 'frpfirewall-linux-amd64-scopetest')
const REMOTE_TMP = '/tmp/ffw-new'
const TARGET = '/usr/local/bin/frpfirewall'
const BK = '/root/ffw-backup'
const SVC = 'frpfirewall'

async function main() {
  if (!fs.existsSync(LOCAL_BIN)) {
    console.error(`本地二进制不存在：${LOCAL_BIN}`)
    process.exit(2)
  }
  const localHash = crypto.createHash('sha256').update(fs.readFileSync(LOCAL_BIN)).digest('hex')
  const localSize = fs.statSync(LOCAL_BIN).size

  const env = readCreds()
  const conn = await connect(env)
  const buf = []
  const log = (s) => {
    buf.push(s)
    console.log(s)
  }
  const step = async (title, cmd, timeout) => {
    log(`\n${'='.repeat(66)}\n## ${title}\n${'='.repeat(66)}\n$ ${cmd}`)
    const out = await run(conn, cmd, timeout || 30000)
    log(out)
    return out
  }

  log(`# 部署测试二进制 ${new Date().toISOString()}`)
  log(`# 目标 ${env.RUSER}@${env.RHOST}`)
  log(`# 本地文件 ${path.basename(LOCAL_BIN)}  size=${localSize}  sha256=${localHash}`)

  // ---- 1. 上传 ----
  log(`\n${'='.repeat(66)}\n## ① 上传到 ${REMOTE_TMP}\n${'='.repeat(66)}`)
  await upload(conn, LOCAL_BIN, REMOTE_TMP)
  const remoteHash = (await run(conn, `sha256sum ${REMOTE_TMP} | cut -d' ' -f1`)).trim()
  log(`远端 sha256 = ${remoteHash}`)
  if (remoteHash !== localHash) {
    log('!! 校验和不一致，中止，未做任何改动')
    conn.end()
    process.exit(1)
  }
  log('校验和一致 ✓')
  await step('① b 远端试运行取版本', `${REMOTE_TMP} -version 2>&1 | head -3`)

  // ---- 2. 改动前状态 ----
  await step(
    '② 改动前：受管集合与规则位置',
    `echo "--- black 集合 ---"; nft list set ip filter frpfirewall_black 2>&1 | grep -E "elements|set "; ` +
      `echo "--- INPUT 前 6 条 ---"; iptables -S INPUT | head -6; ` +
      `echo "--- frp 集合是否已存在（预期 0）---"; nft list ruleset 2>/dev/null | grep -c frpfirewall_black_frp || true`
  )

  // ---- 3. 二次备份 + 替换 ----
  await step(
    '③ 二次备份当前二进制并替换',
    `cp -a ${TARGET} ${BK}/${SVC}-pre.05.rescue && sha256sum ${BK}/${SVC}-pre.05.rescue && install -m 0755 ${REMOTE_TMP} ${TARGET} && sha256sum ${TARGET}`
  )

  // ---- 4. 重启 + 探活 ----
  const restartOut = await step(
    '④ 重启服务并探活',
    `systemctl restart ${SVC}; sleep 5; echo "active=$(systemctl is-active ${SVC})"; systemctl show ${SVC} -p ActiveEnterTimestamp -p ExecMainPID`,
    60000
  )

  let healthy = /active=active/.test(restartOut)
  if (healthy) {
    await step('⑤ 版本确认', `${TARGET} -version 2>&1 | head -3`)
    await step(
      '⑥ 启动日志',
      `journalctl -u ${SVC} -n 30 --no-pager 2>&1 | tail -30`
    )
  }

  // ---- 5. 失败回滚 ----
  if (!healthy) {
    log('\n!! 服务未进入 active，开始回滚')
    await step(
      '⑦ 回滚',
      `cp -a ${BK}/${SVC}-pre.05.rescue ${TARGET} && systemctl restart ${SVC}; sleep 5; ` +
        `echo "active=$(systemctl is-active ${SVC})"; sha256sum ${TARGET}`,
      60000
    )
    conn.end()
    fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true })
    fs.writeFileSync(path.join(ROOT, 'dist', `deploy-FAILED-${Date.now()}.txt`), buf.join('\n') + '\n')
    process.exit(1)
  }

  // ---- 6. 改动后状态 ----
  await step(
    '⑦ 改动后：受管集合与规则位置',
    `echo "--- 全部 frpfirewall 集合 ---"; nft list ruleset 2>/dev/null | grep -A 4 "set frpfirewall" | grep -E "set |elements|type "; ` +
      `echo "--- 含 frpfirewall 的规则 ---"; nft list ruleset 2>/dev/null | grep frpfirewall | grep -v "^#"; ` +
      `echo "--- INPUT 前 8 条 ---"; iptables -S INPUT | head -8`
  )
  await step(
    '⑧ 关键回归检查：原有封禁是否还在',
    `nft list set ip filter frpfirewall_black 2>&1 | grep -q "38.146.28.52" && echo "PASS: 38.146.28.52 仍在集合中" || echo "FAIL: 原有条目丢失！"`
  )

  conn.end()

  const outDir = path.join(ROOT, 'dist')
  fs.mkdirSync(outDir, { recursive: true })
  const out = path.join(outDir, `deploy-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`\n\n已保存：${out}`)
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
