// 用真机实际抓到的内核输出，离线跑一遍修好后的解析与断言逻辑。
//
// 目的：证明验证脚本报出的那 4 个 FAIL 是断言写错（假失败），
// 而不是功能有问题 —— 同时也顺带确认修完之后断言在真实文本上真的能给对结论。
//
// 用法：node tools/assert-selftest.js

// 与 remote-range-test.js 里保持一致的两个解析函数。
function elementsOf(text) {
  const flat = String(text).replace(/\s+/g, ' ')
  const m = /elements = \{([^}]*)\}/.exec(flat)
  if (!m) return []
  return m[1]
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

function parseSections(text) {
  const out = {}
  let cur = '(head)'
  out[cur] = []
  for (const line of String(text).split('\n')) {
    const m = /^\[(.+?)\]$/.exec(line.trim())
    if (m) {
      cur = m[1]
      out[cur] = []
      continue
    }
    out[cur].push(line)
  }
  return out
}

// 下面两段是从 dist/range-test-console.txt 里原样摘出来的真实内核输出，
// 只把标记名换成了新脚本用的名字、把地址换成了文档保留段（RFC 5737），
// 免得把生产机上真实出现过的地址带进仓库。
const dump = [
  '[CHAIN ip filter]',
  '# Warning: table ip filter is managed by iptables-nft, do not touch!',
  '4:\t\tip saddr @frpfirewall_black drop comment "frpfirewall:black"',
  '5:\t\ttcp dport { 7020, 20000-30000 } ip saddr @frpfirewall_black_frp drop comment "frpfirewall:black-frp"',
  '6:\t\tudp dport { 7020, 20000-30000 } ip saddr @frpfirewall_black_frp drop comment "frpfirewall:black-frp"',
  '[CHAIN ip6 filter]',
  '4:\t\tip6 saddr @frpfirewall_black6 drop comment "frpfirewall:black6"',
  '[SETBLACK]',
  'table ip filter {',
  '\tset frpfirewall_black {',
  '\t\ttype ipv4_addr',
  '\t\tflags interval',
  '\t\telements = { 198.51.100.9 }',
  '\t}',
  '}',
  '[SETFRP]',
  'table ip filter {',
  '\tset frpfirewall_black_frp {',
  '\t\ttype ipv4_addr',
  '\t\tflags interval',
  '\t\telements = { 192.0.2.5 }',
  '\t}',
  '}',
].join('\n')

const TEST_BIND_PORT = 7020
const TEST_PROXY_PORTS = '20000-30000'
const TEST_ADDR = '192.0.2.5'

let pass = 0
let fail = 0
function rec(name, ok) {
  if (ok) {
    pass++
    console.log(`  PASS ${name}`)
  } else {
    fail++
    console.log(`  FAIL ${name}`)
  }
}

const sec = parseSections(dump)
const v4rules = (sec['CHAIN ip filter'] || []).join('\n')
const v6rules = (sec['CHAIN ip6 filter'] || []).join('\n')
const squash = (s) => s.replace(/\s+/g, '')
const DPORT = `{${TEST_BIND_PORT},${TEST_PROXY_PORTS}}`

console.log('=== 步骤 6 的断言（喂真实内核输出）===')
rec('v4 链上出现「仅 frp 端口」规则', /comment "frpfirewall:black-frp"/.test(v4rules))
rec(`v4 规则里是区间 ${DPORT}`, squash(v4rules).includes(`dport${DPORT}`))
rec(
  '同一区间在 tcp 与 udp 上都有',
  squash(v4rules).includes(`tcpdport${DPORT}`) && squash(v4rules).includes(`udpdport${DPORT}`),
)
rec('区间没有被展开成逐个端口', !/\b20001\b/.test(dump) && !/\b29999\b/.test(dump))
const frpElems = elementsOf(sec['SETFRP'] || '')
// nft 显示单个主机地址时会把 /32 去掉，所以比较前先剥掩码。
const hostOf = (s) => String(s).split('/')[0]
rec('frp 集合里只有测试地址', frpElems.length === 1 && hostOf(frpElems[0]) === TEST_ADDR)
rec(
  'v4 上 frp 规则条数合理',
  v4rules.split('\n').filter((l) => l.includes('frpfirewall:black-frp')).length === 2,
)
rec('ip6 链上没有多余的 frp 规则', !v6rules.includes('frpfirewall:black-frp'))

console.log('\n=== 步骤 8 的断言（喂真实收尾输出）===')
const after = [
  '[SETBLACK]',
  'table ip filter {',
  '\tset frpfirewall_black {',
  '\t\ttype ipv4_addr',
  '\t\tflags interval',
  '\t\telements = { 198.51.100.9 }',
  '\t}',
  '}',
  '[SETFRP]',
  'table ip filter {',
  '\tset frpfirewall_black_frp {',
  '\t\ttype ipv4_addr',
  '\t\tflags interval',
  '\t}',
  '}',
  '[INPUTRULES]',
  '# Warning: table ip filter is managed by iptables-nft, do not touch!',
  '1',
  '[SERVICE]',
  'active',
].join('\n')
const sec2 = parseSections(after)
rec(
  '全端口集合与基线一致',
  JSON.stringify(elementsOf(sec2['SETBLACK'])) === JSON.stringify(elementsOf(sec['SETBLACK'])),
)
rec('frp 集合已清空', elementsOf(sec2['SETFRP']).length === 0)
rec('服务在运行', /^active/m.test((sec2['SERVICE'] || []).join('\n')))

console.log(`\n通过 ${pass} 项，失败 ${fail} 项`)
process.exit(fail === 0 ? 0 : 1)
