#!/usr/bin/env bash
# 发布说明只保留变更摘要、固定版本的安装入口和文档；完整记录通过 compare 链接查看。
set -euo pipefail

cd "$(dirname "$0")/.."
tag="${1:?用法：bash scripts/release-notes.sh v0.0.1}"
version="${tag#v}"
[[ "$tag" == v* && "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-pre\.[0-9]{2,})?$ ]] || {
  echo "版本标签格式非法：$tag" >&2
  exit 1
}
git rev-parse --verify "${tag}^{commit}" >/dev/null
repo="${GITHUB_REPOSITORY:-dreamstation625/FrpFireWall}"
base="https://github.com/$repo"
docs="$base/blob/$tag"
installer="https://raw.githubusercontent.com/$repo/$tag/scripts/install.sh"

if [[ "$version" == *-pre.* ]]; then
  printf '> 预发布版，适合测试验证。\n\n'
fi
printf '## 更新\n\n'
if [ "$version" = 0.0.1 ]; then
  printf '首个正式版：frp 接入防护、黑白名单、频控封禁与可视化管理。\n\n'
fi
prev="$(git describe --tags --abbrev=0 "${tag}^" 2>/dev/null || true)"
range="$tag"
if [ -n "$prev" ]; then range="$prev..$tag"; fi
# 不把合并、版本号同步等维护提交堆进摘要；完整变更仍可从下方链接查看。
changes="$(git log --no-merges --format='%s' "$range" | awk '
  !/^(chore: 版本升至|\[更新\] (版本升至|发布首个正式版))/ {
    if (++n <= 6) print "- " $0
  }')"
if [ -n "$changes" ]; then printf '%s\n\n' "$changes"; else printf '常规维护更新。\n\n'; fi
if [ -n "$prev" ]; then
  printf '[完整变更](%s/compare/%s...%s)\n\n' "$base" "$prev" "$tag"
else
  printf '[提交记录](%s/commits/%s)\n\n' "$base" "$tag"
fi

printf '## 安装 / 升级\n\n'
printf '> Debian / Ubuntu 优先；操作前备份服务器和防火墙规则。\n\n'
printf '\140\140\140bash\n'
printf '# 安装\ncurl -fsSL %s | sudo bash -s -- --version %s\n\n' "$installer" "$version"
printf '# 升级\ncurl -fsSL %s | sudo bash -s -- update --version %s\n' "$installer" "$version"
printf '\140\140\140\n\n'
printf '附件提供 Linux **amd64 / arm64** 二进制；下载后使用 `sha256sums.txt` 校验。\n\n'
printf '[使用与部署](%s/README.md) · [运维与排障](%s/docs/TROUBLESHOOTING.md)\n' "$docs" "$docs"
