#!/usr/bin/env bash
# 在独立 git 仓库验证首发、更新、预发布、摘要上限及固定版本安装入口。
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/tmp"
sandbox="$(mktemp -d "$root/tmp/release-notes-test.XXXXXX")"
mkdir -p "$sandbox/scripts"
cp "$root/scripts/release-notes.sh" "$sandbox/scripts/"
cd "$sandbox"
git init -q
git config user.name 'Release Test'
git config user.email 'release-test@example.invalid'
git config commit.gpgsign false
git commit -q --allow-empty -m 'feat: 首次发布'
git tag v0.0.1

assert_has() { grep -Fq -- "$2" <<<"$1" || { echo "缺少预期内容：$2" >&2; exit 1; }; }
assert_not() { if grep -Fq -- "$2" <<<"$1"; then echo "出现多余内容：$2" >&2; exit 1; fi; }

first="$(GITHUB_REPOSITORY=example/project bash scripts/release-notes.sh v0.0.1)"
assert_has "$first" 'feat: 首次发布'
assert_has "$first" '/commits/v0.0.1'
assert_has "$first" 'https://raw.githubusercontent.com/example/project/v0.0.1/scripts/install.sh'
assert_has "$first" 'update --version 0.0.1'
assert_not "$first" '预发布版'

for n in {1..8}; do git commit -q --allow-empty -m "fix: 修复 $n"; done
git commit -q --allow-empty -m '[更新] 版本升至 0.0.2-pre.01'
git tag v0.0.2-pre.01
pre="$(bash scripts/release-notes.sh v0.0.2-pre.01)"
assert_has "$pre" '预发布版'
assert_has "$pre" '/compare/v0.0.1...v0.0.2-pre.01'
assert_has "$pre" 'update --version 0.0.2-pre.01'
assert_not "$pre" '[更新] 版本升至'
assert_not "$pre" 'fix: 修复 1'
test "$(grep -c '^- ' <<<"$pre")" = 6

git commit -q --allow-empty -m '[更新] 版本升至 0.0.2'
git tag v0.0.2
maintenance="$(bash scripts/release-notes.sh v0.0.2)"
assert_has "$maintenance" '常规维护更新'
assert_not "$maintenance" '预发布版'
if bash scripts/release-notes.sh 'v0.0.2-rc.1' >/dev/null 2>&1; then exit 1; fi
if bash scripts/release-notes.sh 'v9.9.9' >/dev/null 2>&1; then exit 1; fi
echo '发布说明回归通过：首发、预发布、升级、摘要限制、固定版本与非法标签。'
