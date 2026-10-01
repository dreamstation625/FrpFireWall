'use strict'
// 目标机只读状态一览。给"改完/还原完，现在到底是什么样"这类问题一个固定答案。
//
// 全程只跑查询类命令，不写任何东西（唯一例外：登录换取 token 时会在远端
// 临时落一个文件，退出前删掉）。
//
// 用法：node tools/remote-status.js

const { readCreds, connect, run } = require('./lib/ssh-run')

const BASE = 'http://127.0.0.1:7930/api/v1'
const TOKEN = '/tmp/ffw-status-token'

const sq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'"

;(async () => {
  const env = readCreds()
  const conn = await connect(env)
  const sh = (cmd, t) => run(conn, cmd, t)
  try {
    console.log('===== 二进制 =====')
    console.log(await sh('/usr/local/bin/frpfirewall --version'))

    console.log('\n===== 服务 =====')
    console.log(
      await sh(
        'systemctl is-active frpfirewall; systemctl show -p ActiveEnterTimestamp --value frpfirewall',
      ),
    )

    console.log('\n===== 防火墙上与本程序有关的规则 =====')
    console.log(
      await sh(
        'echo "[v4 INPUT]"; nft list chain ip filter INPUT 2>/dev/null | grep frpfirewall; ' +
          'echo "[v6 INPUT]"; nft list chain ip6 filter INPUT 2>/dev/null | grep frpfirewall; ' +
          'echo "[集合]"; nft list sets 2>/dev/null | grep frpfirewall',
      ),
    )

    console.log('\n===== 集合内容 =====')
    // 解析放到 python 里做：nft 在元素多时会按列宽折行，
    // shell 里用 sed/grep 匹配跨行花括号非常容易得出"集合是空的"这种错结论。
    console.log(
      await sh(
        'for s in "ip filter frpfirewall_black" "ip filter frpfirewall_black_frp" ' +
          '"ip6 filter frpfirewall_black6" "ip6 filter frpfirewall_black6_frp"; do ' +
          'printf "%-46s => " "$s"; ' +
          'nft list set $s 2>/dev/null | python3 -c \'' +
          'import sys,re;t=sys.stdin.read();m=re.search(r"elements = \\{([^}]*)\\}",t,re.S);' +
          'print(" ".join(m.group(1).split()) if m else "(空)")\'; done',
      ),
    )

    console.log('\n===== 接口视角 =====')
    // 登录接口带限流，只调一次，落盘再解析（token 不落到输出里）。
    await sh(
      `curl -s -m 10 -X POST ${sq(BASE + '/auth/login')} -H 'Content-Type: application/json' ` +
        `-d ${sq(JSON.stringify({ username: env.PANEL_USER, password: env.PANEL_PASS }))} > /tmp/ffw-status-login.json`,
    )
    const ok = (
      await sh(
        `python3 -c 'import json;print(json.load(open("/tmp/ffw-status-login.json")).get("ok"))'`,
      )
    ).trim()
    if (ok !== 'True') {
      console.log('  （面板登录失败，跳过接口部分；请检查 .secrets/creds.env 的 PANEL_USER / PANEL_PASS）')
    } else {
      await sh(
        `python3 -c 'import json;print(json.load(open("/tmp/ffw-status-login.json"))["data"]["token"])' > ${TOKEN}`,
      )
      console.log(
        await sh(
          `curl -s -m 10 ${sq(BASE + '/system/info')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
            `| python3 -c 'import sys,json;d=json.load(sys.stdin)["data"];` +
            `print("  版本:",d["version_full"]);` +
            `print("  bind_port:",d["bind_port"]," proxy_ports:",d["proxy_ports"]);` +
            `print("  防护:",d["guard"]["enabled"]," 后端:",d["capability"]["backend"])'`,
        ),
      )
      console.log(
        await sh(
          `curl -s -m 10 ${sq(BASE + '/acl/black?page=1&size=50')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
            `| python3 -c 'import sys,json;d=json.load(sys.stdin)["data"];` +
            `print("  黑名单:",d["total"],"条",[i["target"] for i in d["items"]])'`,
        ),
      )
      console.log(
        await sh(
          `curl -s -m 10 ${sq(BASE + '/bans?page=1&size=50')} -H "Authorization: Bearer $(cat ${TOKEN})" ` +
            `| python3 -c 'import sys,json;d=json.load(sys.stdin)["data"];` +
            `print("  封禁记录:",d["total"],"条")'`,
        ),
      )
    }

    console.log('\n===== 留下的临时文件（应为空）=====')
    console.log(await sh(`rm -f ${TOKEN} /tmp/ffw-status-login.json; ls -la /tmp/ffw* 2>&1 | head -5`))
  } finally {
    conn.end()
  }
})().catch((e) => {
  console.error('失败：', e.message)
  process.exit(1)
})
