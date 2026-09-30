// 从 stdin 读 JSON，按 argv[2] 的点分路径取值打印。
// 数组打印成 [长度]，对象打印成 JSON，便于在 shell 里做断言。
let s = ''
process.stdin.on('data', (d) => (s += d)).on('end', () => {
  let j
  try {
    j = JSON.parse(s)
  } catch (e) {
    console.log('PARSE_ERR:' + s.slice(0, 200))
    return
  }
  const path = process.argv[2] || ''
  let v = j
  for (const k of path.split('.')) {
    if (k === '') continue
    if (v == null) break
    v = v[k]
  }
  if (v === undefined) return console.log('undefined')
  if (v === null) return console.log('null')
  if (Array.isArray(v)) return console.log('[' + v.length + ']')
  if (typeof v === 'object') return console.log(JSON.stringify(v))
  console.log(String(v))
})
