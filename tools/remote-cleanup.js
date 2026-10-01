'use strict'
// 清理验证过程留下的残渣，让目标机回到"只有受管命名空间里该有的东西"。
//
// 两类残渣：
//   1. /tmp 下的临时文件 —— 验证脚本里用 `&&` 串起来的清理，一旦前面某步失败
//      就会被整条跳过，文件就留下了
//   2. 新版建过、回滚后的老版本不认识的空集合（frpfirewall_black*_frp）
//
// 只删自己命名的东西，且删集合前先确认它是空的 —— 不能因为"名字看着像"
// 就把可能装着真实封禁地址的集合删掉。
//
// 用法：node tools/remote-cleanup.js

const { readCreds, connect, run } = require('./lib/ssh-run')

const LEFT_SET_FAMILY = [
  ['ip', 'frpfirewall_black_frp'],
  ['ip6', 'frpfirewall_black6_frp'],
]

;(async () => {
  const env = readCreds()
  const conn = await connect(env)
  const sh = (cmd, t) => run(conn, cmd, t)
  try {
    console.log('===== 删除前 =====')
    console.log(
      await sh(
        'echo "[/tmp 残渣]"; ls -la /tmp/ffw* 2>&1 | head -10; ' +
          'echo "[待清理的集合]"',
      ),
    )

    for (const [family, name] of LEFT_SET_FAMILY) {
      const out = await sh(`nft list set ${family} filter ${name} 2>/dev/null`)
      if (out.includes('<无输出>') || out.trim() === '' || !out.includes('set ' + name)) {
        console.log(`  ${family}/${name}: 不存在，跳过`)
        continue
      }
      // 空集合的判定用 python 做：nft 输出会按列宽折行，跨行匹配花括号不可靠。
      // 注意 run() 在输出为空时会回一个字符串哨兵 "(无输出)"，它是有真值的 ——
      // 不显式剥掉的话，空集合会被当成"里面有元素"，于是永远删不掉。
      const elems = (
        await sh(
          `nft list set ${family} filter ${name} | python3 -c ` +
            `'import sys,re;t=sys.stdin.read();m=re.search(r"elements = \\{([^}]*)\\}",t,re.S);` +
            `print(" ".join(m.group(1).split()) if m else "")'`,
        )
      )
        .trim()
        .replace(/^\(无输出\)$/, '')
      if (elems) {
        console.log(`  ${family}/${name}: 里面有元素（${elems}），**不删**，请人工确认`)
        continue
      }
      const del = await sh(`nft delete set ${family} filter ${name} 2>&1; echo "rc=$?"`)
      console.log(`  ${family}/${name}: ${del.includes('rc=0') ? '已删除（原本为空）' : del}`)
    }

    console.log('\n===== 清理临时文件 =====')
    console.log(
      await sh(
        'rm -f /tmp/ffw-new /tmp/ffw-token /tmp/ffw-login.json /tmp/ffw-status-token ' +
          '/tmp/ffw-status-login.json /tmp/ffw-cfg-range.json /tmp/ffw-cfg-restore.json ' +
          '/tmp/ffw-cfg-rollback.json /tmp/nftcheck.nft; ' +
          'echo "[清理后]"; ls -la /tmp/ffw* /tmp/nftcheck.nft 2>&1 | head -5',
      ),
    )

    console.log('\n===== 清理后受管命名空间 =====')
    console.log(
      await sh(
        'echo "[v4 INPUT]"; nft list chain ip filter INPUT 2>/dev/null | grep frpfirewall; ' +
          'echo "[v6 INPUT]"; nft list chain ip6 filter INPUT 2>/dev/null | grep frpfirewall; ' +
          'echo "[集合名]"; nft list sets 2>/dev/null | grep -o "frpfirewall_[a-z0-9_]*" | sort -u',
      ),
    )
    console.log(`  服务: ${await sh('systemctl is-active frpfirewall')}`)
  } finally {
    conn.end()
  }
})().catch((e) => {
  console.error('失败：', e.message)
  process.exit(1)
})
