#!/usr/bin/env bash
#
# version-bump.sh —— 把版本号同步改到全部四处。
#
# 为什么要有这个脚本：
#   版本号散落在四个文件里，只改 VERSION 是**不够**的 ——
#   internal/version 里有一条 TestDefaultVersionMatchesVersionFile，
#   专门拿默认值跟 VERSION 文件对账。漏改的后果不是编译失败，而是
#   CI 挂在单元测试那一步；如果 tag 已经推上去了，Release 会在同一个
#   位置失败，且失败前不会产出任何 Release 资产，看起来像"发版挂了但
#   说不上哪儿挂了"。手动改过两次，两次都漏，所以做成脚本。
#
# 四处是：
#   VERSION                             整个文件
#   internal/version/version.go         Version 默认值（裸 go build 用）
#   web/package.json                    项目版本
#   web/package-lock.json               根 version 与 packages[""] 各一处
#
# 用法：
#   scripts/version-bump.sh 0.0.1-pre.07
#
# 只接受 0.0.1 与 0.0.1-pre.NN 两种形态（NN 补零到两位），与
# internal/version、scripts/install.sh、Release 工作流的判定保持一致。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

V="${1:-}"
if [ -z "$V" ]; then
  echo "用法：$0 0.0.1-pre.07" >&2
  exit 1
fi

# 与 Release 工作流里的正则同源，别各写一套。
if ! printf '%s' "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-pre\.[0-9]{2,})?$'; then
  echo "版本号格式非法：$V" >&2
  echo "只接受 0.0.1 或 0.0.1-pre.01 两种形态（预发布序号补零到两位）。" >&2
  exit 1
fi

FILES=(VERSION internal/version/version.go web/package.json web/package-lock.json)
for f in "${FILES[@]}"; do
  test -f "$f" || { echo "缺少文件：$f（请在仓库根目录执行）" >&2; exit 1; }
done

OLD="$(tr -d ' \t\r\n' < VERSION)"
if [ "$OLD" = "$V" ]; then
  echo "四处已经是 $V，无需改动"
  exit 0
fi

echo "$OLD → $V"

# 点号要转义，否则 0.0.1-pre.05 里的点在正则里会匹配任意字符。
OLD_RE="$(printf '%s' "$OLD" | sed 's/[.]/\\./g')"
NEW_RE="$(printf '%s' "$V" | sed 's/[.]/\\./g')"

# 用显式临时文件而不是 sed -i：GNU 与 BSD 的 -i 语义不同（后者要求跟一个
# 参数），而 sed -i.bak 会在工作区留下 .bak 文件 —— 一旦哪一步提前退出，
# 那些文件就留在 git status 里了。
replace_in() {
  local f="$1" tmp
  tmp="$(mktemp)"
  sed "s/\"$OLD_RE\"/\"$V\"/g" "$f" > "$tmp"
  mv "$tmp" "$f"
}

printf '%s\n' "$V" > VERSION
for f in internal/version/version.go web/package.json web/package-lock.json; do
  replace_in "$f"
done

# 改完必须自己数一遍：少改一处的表现是"测试挂了"，而不是"这个脚本错了"，
# 所以在脚本里就把话说清楚。
#
# 两点都踩过：
#   · 只数「带引号的版本号」。sed 换的就是这个形态。不带引号的旧版本号
#     （注释里写的历史沿革、"上一版是 0.0.1-pre.05" 之类）本来就不该被改，
#     把它算成漏改会让改成功的调用反而以非 0 退出。
#   · grep ... || true：本脚本开了 set -o pipefail，而 grep 在"一处都不剩"
#     时返回 1 —— 那恰恰是想看到的成功情形。不兜住的话管道整体状态为 1，
#     再被 set -e 一判，脚本会在"改成功了"的这一步静默退出。
left="$( { grep -rn "\"$OLD_RE\"" "${FILES[@]}" 2>/dev/null || true; } | wc -l | tr -d ' ')"
if [ "$left" != "0" ]; then
  echo "仍有 $left 处写着 \"$OLD\"，请手动核对：" >&2
  grep -rn "\"$OLD_RE\"" "${FILES[@]}" >&2 || true
  exit 1
fi

echo "已同步四处："
grep -n "\"$NEW_RE\"" "${FILES[@]}" || true
