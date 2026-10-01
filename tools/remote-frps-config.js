#!/usr/bin/env node
'use strict'
// 读目标机上 frps 的真实配置（含容器内的情形），用于核对面板里的
// bind_port / proxy_ports 是否与实际一致。
//
// 只读。凭据类字段经 redact 脱敏。
//
// 用法：NODE_PATH=... node tools/remote-frps-config.js

const { readCreds, connect, run, redact } = require('./lib/ssh-run')

// frps 常跑在 docker 里，宿主文件系统上看不到它的 /data。
// 容器 ID 从 cgroup 拿：cat /proc/<pid>/cgroup
const CMD = `
echo "=== frps 进程 ==="
ps -eo pid,etime,args | grep "[f]rps" | head -3
echo
echo "=== 宿主能否直接看到 ==="
ls -la /data/frps-1.json 2>&1 | head -2
echo
echo "=== 进程所属容器 ==="
PID=$(pgrep -f "[f]rps" | head -1)
CGROUP=$(cat /proc/$PID/cgroup 2>/dev/null | head -1)
echo "$CGROUP"
CID=$(printf '%s' "$CGROUP" | grep -oE '[0-9a-f]{64}' | head -1)
echo "container=$CID"
echo
echo "=== docker ps ==="
docker ps --format '{{.ID}}  {{.Names}}  {{.Image}}' 2>&1 | head -8
echo
echo "=== 容器内 /data 目录 ==="
docker exec "$CID" ls -la /data/ 2>&1 | head -20
echo
echo "=== frps 配置文件（凭据值已脱敏）==="
docker exec "$CID" cat /data/frps-1.json 2>&1 | head -100
echo
echo "=== 容器内 frps 版本 ==="
docker exec "$CID" /data/bin/frps --version 2>&1 | head -2
`

async function main() {
  const env = readCreds()
  const conn = await connect(env)
  const out = await run(conn, CMD, 60000)
  console.log(redact(out))
  conn.end()
}

main().catch((e) => {
  console.error(`失败：${e.message}`)
  process.exit(1)
})
