'use strict'
// nft 区间语法预检（只读，不落任何规则）。
//
// 本轮改动的唯一语法风险就在这：nft 的匿名集合里到底认不认 `20000-30000`。
// 如果它不认，驱动那边的 `nft -c` 预检会整份放弃，表现为"一条规则都不下发"，
// 而不是某条规则失败 —— 所以必须在动手之前先把这个问题问清楚。
//
// 用 `nft -c -f -`（check 模式）验证：解析并做语义检查，但不提交。

const { readCreds, connect, run } = require('./lib/ssh-run')

// 一条条试，每条都单独给出结论，避免一条失败就掩盖了其它几条的真实情况。
const CASES = [
  ['单端口集合（现状）', 'tcp dport { 80, 443 } drop'],
  ['区间混在集合里', 'tcp dport { 80, 20000-30000 } drop'],
  ['纯区间集合', 'tcp dport { 20000-30000 } drop'],
  ['udp 区间', 'udp dport { 20000-30000 } drop'],
  ['单一区间不写成集合', 'tcp dport 20000-30000 drop'],
  ['超长端口列表（对照组）', 'tcp dport { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 } drop'],
]

function shellSingleQuote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'"
}

;(async () => {
  const env = readCreds()
  const conn = await connect(env)
  try {
    console.log('### 目标机 nft 版本')
    console.log(await run(conn, 'nft --version'))

    console.log('\n### 匿名集合区间语法预检（nft -c，不提交）')
    for (const [name, rule] of CASES) {
      // 构造一份最小可校验的脚本：独立表、独立链，加 check 模式，绝不落到系统表上。
      // 注意链内每条规则要用 `;` 或换行收尾 —— 漏了会让整份脚本报
      // "unexpected end of file"，看起来像是规则本身有问题，其实是格式问题。
      const script =
        `table ip frpfirewall_syntaxcheck\n` +
        `delete table ip frpfirewall_syntaxcheck\n` +
        `table ip frpfirewall_syntaxcheck {\n` +
        `  chain probe { type filter hook input priority 10; policy accept; ${rule}; }\n` +
        `}\n`
      const b64 = Buffer.from(script).toString('base64')
      const cmd =
        `echo ${b64} | base64 -d > /tmp/nftcheck.nft; ` +
        `if nft -c -f /tmp/nftcheck.nft 2>&1; then echo "OK"; else echo "REJECTED"; fi; ` +
        `rm -f /tmp/nftcheck.nft`
      const out = await run(conn, cmd, 15000)
      const ok = out.includes('OK') && !out.includes('REJECTED')
      console.log(`  [${ok ? 'OK  ' : '拒绝'}] ${name}`)
      if (!ok) console.log(`         ${out.replace(/\n/g, '\n         ')}`)
    }

    console.log('\n### 确认没有留下任何东西')
    console.log(await run(conn, 'nft list tables | grep -c syntaxcheck || echo "0（干净）"'))

    console.log('\n### iptables multiport 的区间写法')
    // 只用 -C（检查）不用 -A：退出码 1 表示"规则不存在"（说明语法被接受），
    // 2 表示参数/语法错误。绝不往任何链里写东西。
    console.log(
      await run(
        conn,
        'command -v iptables >/dev/null || { echo "本机没有 iptables"; exit 0; }; ' +
          'iptables -w -C INPUT -p tcp -m multiport --dports 20000:30000,80 -j ACCEPT; ' +
          'echo "退出码=$?（1=规则不存在但语法被接受，2=语法或参数错误）"; ' +
          'echo "--- 对照组：故意用 nft 风格的 lo-hi ---"; ' +
          'iptables -w -C INPUT -p tcp -m multiport --dports 20000-30000 -j ACCEPT; ' +
          'echo "退出码=$?"',
        15000,
      ),
    )
  } finally {
    conn.end()
  }
})().catch((e) => {
  console.error('失败：', e.message)
  process.exit(1)
})
