'use strict'
// 远程执行与传输的公共层。
//
// 存在的理由：这一轮的验证要反复连同一台机器（侦察 → 备份 → 传二进制 → 核验），
// 每个脚本各写一份连接代码，迟早出现"某个脚本忘了 trim 密码"这类漂移。
// 凭据读取、脱敏、超时这三件事只做一次。
//
// 依赖：ssh2（装在受管 node 工作区）
//   NODE_PATH=C:/Users/dream/.workbuddy/binaries/node/workspace/node_modules

const fs = require('node:fs')
const path = require('node:path')
const { Client } = require('ssh2')

const ROOT = path.resolve(__dirname, '..', '..')
const DEFAULT_CREDS = path.join(ROOT, '.secrets', 'creds.env')

// 命中这些词的行，值一律不回显。
// 宽松是故意的：宁可多脱敏几行，也不要漏一条 token 进对话记录。
const SECRET_KEY_RE =
  /(token|password|passwd|pwd|secret|api[_-]?key|apikey|authorization|credential|private[_-]?key|passphrase)/i

function readCreds(file) {
  const f = file || process.env.CREDS_FILE || DEFAULT_CREDS
  if (!fs.existsSync(f)) {
    throw new Error(`找不到凭据文件：${f}`)
  }
  const env = {}
  for (const raw of fs.readFileSync(f, 'utf8').split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const i = line.indexOf('=')
    if (i <= 0) continue
    env[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  for (const k of ['RHOST', 'RPORT', 'RUSER', 'RPASS', 'RKEY', 'RKEY_PASSPHRASE']) {
    if (process.env[k]) env[k] = process.env[k]
  }
  if (!env.RHOST || !env.RUSER) throw new Error('creds.env 里 RHOST / RUSER 还没填。')
  if (!env.RKEY && !env.RPASS) throw new Error('creds.env 里 RKEY 和 RPASS 都没填，无法登录。')
  return env
}

function buildConfig(env) {
  const cfg = {
    host: env.RHOST,
    port: Number(env.RPORT || 22),
    username: env.RUSER,
    // 目标机 host key 变化时不要让脚本卡在交互提示上；
    // 指纹核对在首次连接时人工做一次即可。
    readyTimeout: 20000,
    keepaliveInterval: 10000,
  }
  if (env.RKEY) {
    cfg.privateKey = fs.readFileSync(env.RKEY)
    if (env.RKEY_PASSPHRASE) cfg.passphrase = env.RKEY_PASSPHRASE
  } else {
    cfg.password = env.RPASS
  }
  return cfg
}

function connect(env) {
  const conn = new Client()
  return new Promise((resolve, reject) => {
    conn
      .on('ready', () => resolve(conn))
      .on('error', reject)
      .connect(buildConfig(env))
  })
}

// 单条命令执行。必须有超时 —— 一条 `ss -lntup` 卡住的代价是整个验证流程停摆。
function run(conn, cmd, timeoutMs) {
  const limit = timeoutMs || 30000
  return new Promise((resolve) => {
    let settled = false
    const done = (s) => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        resolve(s)
      }
    }
    const timer = setTimeout(() => done(`<超时 ${limit}ms>`), limit)

    conn.exec(cmd, (err, stream) => {
      if (err) return done(`<执行失败: ${err.message}>`)
      let out = ''
      const MAX = 512 * 1024
      stream.on('data', (d) => {
        if (out.length < MAX) out += d
      })
      stream.stderr.on('data', (d) => {
        if (out.length < MAX) out += d
      })
      stream.on('close', () => done(out.trim() || '(无输出)'))
    })
  })
}

// 上传。用 fastPut 而不是流，省掉手动管 close 事件。
function upload(conn, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err)
      sftp.fastPut(localPath, remotePath, (e) => (e ? reject(e) : resolve(remotePath)))
    })
  })
}

// 把敏感行的值替换成长度占位。保留键名 —— 排查"配置项有没有写"时键名就够了。
function redact(text) {
  return String(text)
    .split('\n')
    .map((line) => {
      if (!SECRET_KEY_RE.test(line)) return line
      const m = line.match(/^(\s*[\w.\-"'\[\]\/]*\s*[:=]\s*)(.*)$/)
      if (m) {
        const v = m[2].replace(/["',\s]/g, '')
        return `${m[1]}<redacted len=${v.length}>`
      }
      return '<redacted>'
    })
    .join('\n')
}

module.exports = { ROOT, readCreds, buildConfig, connect, run, upload, redact }
