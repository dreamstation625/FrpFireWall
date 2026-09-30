// 读 stdin 的 JSON 对象，按 argv 的 key=value 覆盖字段后输出。
//
//   · 值自动识别类型：true/false -> 布尔，null -> null，纯数字 -> 数字，其余按字符串
//   · key 支持点分路径，例：log.level=debug  server.tls.enabled=true
//   · 参数以 '-' 开头表示删除该字段，例：-id -updated_at -server.tls
//
// 例：node mutate.js ban_durations=600,3600,0 rate_limit_enabled=true -id
//     node mutate.js frps.plugin_listen=0.0.0.0:9100
//
// 注意 STRING_KEYS：这些字段在后端是 string 类型，即使内容全是数字也不能转成数字，
// 否则 Go 侧 json.Unmarshal 会直接失败（表现为 400 请求格式不正确）。
const STRING_KEYS = new Set([
  'ban_durations',
  'geoip_block_countries',
  'fail_mode',
  'ban_granularity',
  'geoip_mode',
])

function setPath(obj, path, value) {
  const parts = path.split('.')
  let cur = obj
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i]
    if (cur[p] === null || typeof cur[p] !== 'object') cur[p] = {}
    cur = cur[p]
  }
  cur[parts[parts.length - 1]] = value
}

function delPath(obj, path) {
  const parts = path.split('.')
  let cur = obj
  for (let i = 0; i < parts.length - 1; i++) {
    cur = cur[parts[i]]
    if (cur === null || typeof cur !== 'object') return
  }
  delete cur[parts[parts.length - 1]]
}

let s = ''
process.stdin.on('data', (d) => (s += d)).on('end', () => {
  let j
  try {
    j = JSON.parse(s)
  } catch (e) {
    console.error('输入不是合法 JSON')
    process.exit(1)
  }
  if (j === null || typeof j !== 'object') {
    console.error('输入不是 JSON 对象')
    process.exit(1)
  }

  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith('-')) {
      delPath(j, arg.slice(1))
      continue
    }
    const i = arg.indexOf('=')
    if (i < 0) continue
    const k = arg.slice(0, i)
    const raw = arg.slice(i + 1)
    const leaf = k.split('.').pop()

    let v
    if (raw === 'null') v = null
    else if (STRING_KEYS.has(leaf)) v = raw
    else if (raw === 'true') v = true
    else if (raw === 'false') v = false
    else if (/^[[{]/.test(raw)) {
      // 数组 / 对象字面量直接按 JSON 解析，例：trusted_proxies=["1.2.3.0/24"]
      try {
        v = JSON.parse(raw)
      } catch {
        v = raw
      }
    } else if (raw !== '' && !isNaN(Number(raw))) v = Number(raw)
    else v = raw

    setPath(j, k, v)
  }

  console.log(JSON.stringify(j))
})
