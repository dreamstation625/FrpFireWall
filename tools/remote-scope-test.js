#!/usr/bin/env node
'use strict'
// 黑名单范围（scope）功能的真机验证。
//
// 测试地址一律用 192.0.2.0/24（RFC 5737 TEST-NET-1）—— 真实流量永远不会来自
// 这个网段，所以即使规则真的落到生产机上，也碰不到任何一条业务报文。
//
// 断言全部基于内核实况（nft/iptables 的输出），而不是只看接口返回。
// 无论中途成败，finally 里都会删掉测试条目，把现场恢复回去。
//
// 用法：NODE_PATH=... node tools/remote-scope-test.js

const path = require('node:path')
const fs = require('node:fs')
const { ROOT, readCreds, connect, run } = require('./lib/ssh-run')

const BASE = 'http://127.0.0.1:7930/api/v1'
const T_FRP = '192.0.2.5'
const T_ALL = '192.0.2.6'

// 把输出切成 [标记] 段落，避免跨段正则误匹配。
// 尤其是 frpfirewall:black 是 frpfirewall:black-frp 的前缀，裸 contains 会把
// 「全端口规则」和「frp 规则」认成同一条 —— 单测里已经栽过一次。
function sections(text) {
  const out = {}
  let cur = null
  for (const line of text.split('\n')) {
    const m = line.match(/^\[([A-Za-z0-9_ .-]+?)\]\s?(.*)$/)
    if (m) {
      cur = m[1]
      out[cur] = m[2]
      continue
    }
    if (cur) out[cur] = out[cur] + '\n' + line
  }
  return out
}

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
  let pass = 0
  let fail = 0
  const check = (name, cond, detail) => {
    if (cond) pass++
    else fail++
    log(`>>> ${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '   [' + detail + ']' : ''}`)
  }

  // ---- 登录 ----
  const loginRaw = await run(
    conn,
    `curl -s -m 10 -X POST ${BASE}/auth/login -H 'Content-Type: application/json' ` +
      `-d '{"username":"${env.PANEL_USER}","password":"${env.PANEL_PASS}"}'`
  )
  const token = JSON.parse(loginRaw).data.token
  await run(conn, `umask 077; printf '%s' '${token}' > /tmp/ffw-token`)

  // URL 整体加引号，否则查询串里的 & 会被 shell 当成后台执行符
  const api = (m, p, body) =>
    `curl -s -m 20 -X ${m} "${BASE}${p}" -H "Authorization: Bearer $(cat /tmp/ffw-token)" ` +
    `-H 'Content-Type: application/json' ${body ? `-d '${JSON.stringify(body)}'` : ''}`

  const probeKernel = async (title) => {
    // 规则下发是异步的：API 走 Refresh(重载内存) + Apply(向 applyCh 发信号)，
    // tickLoop 收到信号后还要等 150ms 防抖才 Reconcile。
    // 不等待就探测，看到的一定是上一轮的状态（表现为"落后一拍"）。
    await run(conn, 'sleep 2')
    const raw = await step(
      title,
      // 必须先把换行压平：元素多时 nft 会按列宽折行输出，
      // 直接 grep 'elements = {...}' 会因为花括号跨行而匹配不到，
      // 表现为"集合不存在"，把正确的内核状态误判成失败。
      `for s in "ip filter frpfirewall_black" "ip filter frpfirewall_black_frp" "ip6 filter frpfirewall_black6" "ip6 filter frpfirewall_black6_frp"; do ` +
        `printf "[SET %s] " "$s"; nft list set $s 2>/dev/null | tr -s " \\t\\n" " " | grep -o "elements = {[^}]*}" || echo "(无 elements 行)"; done; ` +
        `printf "[RULES4]\\n"; nft -a list chain ip filter INPUT 2>&1 | grep frpfirewall || echo "(无)"; ` +
        `printf "[RULES6]\\n"; nft -a list chain ip6 filter INPUT 2>&1 | grep frpfirewall || echo "(无)"; ` +
        `printf "[IPT]\\n"; iptables -S INPUT | head -7`
    )
    return sections(raw)
  }

  const ids = {}
  try {
    log(`# scope 功能真机验证 ${new Date().toISOString()}`)
    log(`# 测试地址 ${T_FRP}（frp 范围）/ ${T_ALL}（全端口）—— 均属 RFC 5737 测试网段，不可能是真实业务流量`)

    const k0 = await probeKernel('① 基线：下发前')
    const baseAll = k0['SET ip filter frpfirewall_black'] || ''
    const baseFrp = k0['SET ip filter frpfirewall_black_frp'] || ''

    // ---- 2. scope=frp ----
    const c1 = await step(
      `② 新增黑名单 ${T_FRP}，scope=frp`,
      api('POST', '/acl/black', { target: T_FRP, scope: 'frp', remark: 'scope验证-frp' })
    )
    ids.frp = JSON.parse(c1).data.id
    const k1 = await probeKernel('③ 内核实况（frp 条目）')
    const e1All = k1['SET ip filter frpfirewall_black'] || ''
    const e1Frp = k1['SET ip filter frpfirewall_black_frp'] || ''
    const r1 = (k1['RULES4'] || '').trim()

    log(`\n--- 提取结果 ---\n全端口集合: ${e1All}\nfrp 集合  : ${e1Frp}`)
    check('接口返回的 scope = frp', JSON.parse(c1).data.scope === 'frp')
    check(`frp 集合包含 ${T_FRP}`, e1Frp.includes(T_FRP), e1Frp)
    check(`全端口集合不含 ${T_FRP}`, !e1All.includes(T_FRP), e1All)
    check('原有 38.146.28.52 未被影响', e1All.includes('38.146.28.52'))
    check('生成了 frp 规则（带 comment）', r1.includes('frpfirewall:black-frp'))
    check('规则覆盖 tcp', /tcp dport \{/.test(r1))
    check('规则覆盖 udp（否则 UDP 代理端口可绕过）', /udp dport \{/.test(r1))
    check('dport 含 bind_port 7000', /tcp dport \{[^}]*7000[^}]*\}/.test(r1))
    check('dport 含 proxy_port 80', /tcp dport \{[^}]*\b80\b[^}]*\}/.test(r1))
    check('dport 含 proxy_port 443', /tcp dport \{[^}]*443[^}]*\}/.test(r1))
    check('该规则限定在 frp 集合上', /saddr @frpfirewall_black_frp/.test(r1))

    // ---- 4. scope=all ----
    const c2 = await step(
      `④ 新增黑名单 ${T_ALL}，scope=all`,
      api('POST', '/acl/black', { target: T_ALL, scope: 'all', remark: 'scope验证-all' })
    )
    ids.all = JSON.parse(c2).data.id
    const k2 = await probeKernel('⑤ 内核实况（两个条目）')
    const e2All = k2['SET ip filter frpfirewall_black'] || ''
    const e2Frp = k2['SET ip filter frpfirewall_black_frp'] || ''
    const r2 = (k2['RULES4'] || '').trim()

    log(`\n--- 提取结果 ---\n全端口集合: ${e2All}\nfrp 集合  : ${e2Frp}`)
    check(`全端口集合包含 ${T_ALL}`, e2All.includes(T_ALL), e2All)
    check(`全端口集合不含 ${T_FRP}（各归其位）`, !e2All.includes(T_FRP))
    check(`frp 集合仍只含 ${T_FRP}`, e2Frp.includes(T_FRP) && !e2Frp.includes(T_ALL))

    // 链上顺序
    const rl = r2.split('\n')
    const iAll = rl.findIndex((l) => l.includes('frpfirewall:black"'))
    const iFrp = rl.findIndex((l) => l.includes('frpfirewall:black-frp'))
    check('链上顺序：全端口规则先于 frp 规则', iAll >= 0 && iFrp >= 0 && iAll < iFrp, `all@${iAll} frp@${iFrp}`)

    // ---- 6. 回归守卫 ----
    await step(
      '⑥ 只改备注、不传 scope（回归守卫：不得放宽范围）',
      api('PUT', `/acl/black/${ids.frp}`, { remark: '只改了备注' })
    )
    const k3 = await probeKernel('⑦ 内核实况（改备注后）')
    check(`${T_FRP} 仍在 frp 集合`, (k3['SET ip filter frpfirewall_black_frp'] || '').includes(T_FRP))
    check(`未被放宽到全端口集合`, !(k3['SET ip filter frpfirewall_black'] || '').includes(T_FRP))

    // ---- 8. 显式改范围 ----
    await step(`⑧ 显式把 ${T_FRP} 的 scope 改成 all`, api('PUT', `/acl/black/${ids.frp}`, { scope: 'all' }))
    const k4 = await probeKernel('⑨ 内核实况（改范围后）')
    check(`${T_FRP} 已移入全端口集合`, (k4['SET ip filter frpfirewall_black'] || '').includes(T_FRP))
    check(`${T_FRP} 已从 frp 集合移除`, !(k4['SET ip filter frpfirewall_black_frp'] || '').includes(T_FRP))

    // ---- 10. 非法值 ----
    const bad = await step('⑩ 非法 scope 应被拒', api('POST', '/acl/black', { target: '192.0.2.7', scope: 'port' }))
    check('非法 scope 返回错误且提示取值', /"ok":false/.test(bad) && /all/.test(bad) && /frp/.test(bad))

    // ---- 11. 白名单 ----
    const w = await step('⑪ 白名单传 scope=frp 应被忽略成 all', api('POST', '/acl/white', { target: '192.0.2.8', scope: 'frp' }))
    check('白名单条目 scope=all', JSON.parse(w).data.scope === 'all')
    ids.white = JSON.parse(w).data.id

    // ---- 12. 导入格式 ----
    const imp = await step(
      '⑫ 批量导入：新三列格式 + 老两列格式兼容（dry_run）',
      api('POST', '/acl/black/import', {
        content: '192.0.2.20,frp,带范围\n192.0.2.21,只是备注\n192.0.2.22',
        dry_run: true,
      })
    )
    check('老格式行仍可导入（不作废）', /"ok":true/.test(imp))
    log(`\n导入 dry-run 结果：${imp}`)

    // ---- 13. 导出格式 ----
    const exp = await step('⑬ 导出：黑名单应为 地址,范围,备注 三列', api('GET', '/acl/black/export'))
    log(`\n导出结果：${exp.slice(0, 600)}`)
  } finally {
    log(`\n${'='.repeat(66)}\n## 清理（无论成败都执行）\n${'='.repeat(66)}`)
    for (const [k, id] of Object.entries(ids)) {
      if (!id) continue
      const kind = k === 'white' ? 'white' : 'black'
      log(`删除 ${kind}/${id}: ${await run(conn, api('DELETE', `/acl/${kind}/${id}`))}`)
    }
    log(`清理后黑名单：${await run(conn, api('GET', '/acl/black?page=1&size=50'))}`)
    await probeKernel('清理后内核状态（应与基线一致）')
    await run(conn, `rm -f /tmp/ffw-token`)
  }

  log(`\n\n===== 汇总：PASS ${pass} / FAIL ${fail} =====`)
  conn.end()

  const outDir = path.join(ROOT, 'dist')
  fs.mkdirSync(outDir, { recursive: true })
  const out = path.join(outDir, `remote-scope-test-${Date.now()}.txt`)
  fs.writeFileSync(out, buf.join('\n') + '\n')
  console.log(`已保存：${out}`)
  process.exit(fail > 0 ? 1 : 0)
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
