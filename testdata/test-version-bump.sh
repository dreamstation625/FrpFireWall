#!/usr/bin/env bash
#
# test-version-bump.sh —— scripts/version-bump.sh 的回归测试。
#
# 为什么值得单独测：
#   版本号散在四处，漏改一处的表现**不是**脚本报错，而是单元测试挂在
#   internal/version 那条对账用例上。如果 tag 已经推了，Release 会在同一个
#   位置失败，且失败前不产出任何资产 —— 排查起来只能看 CI 日志。
#   所以这里把"四处都改到了"直接测出来。
#
# 安全边界：
#   全部用例都在临时沙盒里跑，用的是脚本的副本；仓库里真实的 VERSION /
#   version.go / package*.json 一次都不会被写到。文件末尾还有一道显式守卫
#   （比对本测试开始前后的校验和），真跑歪了会直接报出来。
#
# 用法： bash testdata/test-version-bump.sh
set -u

cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
REAL_SCRIPT="$ROOT/scripts/version-bump.sh"

PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m' "$1"; }
green() { printf '\033[32m%s\033[0m' "$1"; }

section() { printf '\n########## %s ##########\n' "$*"; }

ck() { # 描述 实际 期望
  if [ "$2" = "$3" ]; then
    printf '  %s %-46s %s\n' "$(green PASS)" "$1" "$2"; PASS=$((PASS + 1))
  else
    printf '  %s %-46s got=%s want=%s\n' "$(red FAIL)" "$1" "$2" "$3"; FAIL=$((FAIL + 1))
  fi
}

ck_has() { # 描述 文本 关键词
  case "$2" in
    *"$3"*) printf '  %s %-46s 命中「%s」\n' "$(green PASS)" "$1" "$3"; PASS=$((PASS + 1)) ;;
    *)      printf '  %s %-46s 未命中「%s」\n' "$(red FAIL)" "$1" "$3"
            printf '        实际：%s\n' "$2"
            FAIL=$((FAIL + 1)) ;;
  esac
}

ck_reject() { # 描述 版本号（可空）
  local desc="$1" v="${2:-}" out rc
  out="$(bash "$SB/scripts/version-bump.sh" $v 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    printf '  %s %-46s 却被接受了\n' "$(red FAIL)" "$desc"; FAIL=$((FAIL + 1))
  else
    printf '  %s %-46s\n' "$(green PASS)" "$desc"; PASS=$((PASS + 1))
  fi
}

# 仓库里四个文件的校验和，用于开头 / 结尾各取一次做守卫。
repo_fingerprint() {
  cat "$ROOT/VERSION" \
      "$ROOT/internal/version/version.go" \
      "$ROOT/web/package.json" \
      "$ROOT/web/package-lock.json" 2>/dev/null | cksum
}

# 每个用例一个新目录，绝不复用、也不删旧目录 —— MSYS 下对临时路径做 rm -rf
# 会碰到 safe-delete 护栏（embedded drive prefix is not allowed）而静默失败，
# 上一次的残留文件会污染下一次的断言。统一挂在同一个根下，退出时一次清掉。
SANDBOX_ROOT="$(mktemp -d)"
# 退出时清掉。MSYS 的 mktemp 回的是 "C:\...\Temp/tmp.xxx" 这种混合路径，
# 直接 rm 会被环境的 safe-delete 护栏拒掉（embedded drive prefix）并在
# 每次运行都打一行警告，所以先转成 /c/... 形态。
cleanup() {
  local p="$SANDBOX_ROOT"
  if command -v cygpath >/dev/null 2>&1; then
    p="$(cygpath -u "$p" 2>/dev/null || printf '%s' "$p")"
  fi
  rm -rf "$p" 2>/dev/null || true
}
trap cleanup EXIT
SB_COUNT=0

mk_sandbox() { # 起始版本 [故意不创建的文件]
  local v="$1" skip="${2:-}"
  SB_COUNT=$((SB_COUNT + 1))
  SB="$SANDBOX_ROOT/sb$SB_COUNT"
  mkdir -p "$SB/scripts" "$SB/internal/version" "$SB/web"
  cp "$REAL_SCRIPT" "$SB/scripts/version-bump.sh"

  printf '%s\n' "$v" > "$SB/VERSION"

  # 里面刻意放一条不带引号的旧版本号：sed 只替换带引号的形态，
  # 注释里的历史版本号不该被动。
  if [ "$skip" != "internal/version/version.go" ]; then
    cat > "$SB/internal/version/version.go" <<EOF
package version

var (
	Version   = "$v"
	Commit    = "unknown"
)

// 历史：$v 之前是 0.0.1-pre.01
EOF
  fi

  if [ "$skip" != "web/package.json" ]; then
    cat > "$SB/web/package.json" <<EOF
{
  "name": "frpfw-web",
  "version": "$v",
  "private": true
}
EOF
  fi

  # 真实的 lock 文件里有一百多条依赖各自的 version，都不该被碰。
  if [ "$skip" != "web/package-lock.json" ]; then
    cat > "$SB/web/package-lock.json" <<EOF
{
  "name": "frpfw-web",
  "version": "$v",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "frpfw-web",
      "version": "$v"
    },
    "node_modules/vue": {
      "version": "3.5.43"
    }
  }
}
EOF
  fi
}

count_in() { # 文件 字符串
  grep -c -- "$2" "$1" 2>/dev/null || true
}

OLD="0.0.1-pre.05"
NEW="0.0.1-pre.06"

mk_sandbox "$OLD"
REPO_BEFORE="$(repo_fingerprint)"

# ---------------------------------------------------------------------------
section "语法检查"
# ---------------------------------------------------------------------------
if bash -n "$REAL_SCRIPT" 2>/dev/null; then
  printf '  %s %-46s\n' "$(green PASS)" "version-bump.sh 语法检查通过"; PASS=$((PASS + 1))
else
  printf '  %s %-46s\n' "$(red FAIL)" "version-bump.sh 语法检查未通过"; FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
section "版本号格式校验（在沙盒副本上跑）"
# ---------------------------------------------------------------------------
# 与 internal/version、scripts/install.sh、Release 工作流同源：
# 只认 0.0.1 与 0.0.1-pre.NN（NN 补零到两位）。
ck_reject "无参数时报错"
ck_reject "拒绝「1.2」"            "1.2"
ck_reject "拒绝「v0.0.1」"          "v0.0.1"
ck_reject "拒绝「0.0.1-pre」"       "0.0.1-pre"
ck_reject "拒绝「0.0.1-pre.1」"     "0.0.1-pre.1"
ck_reject "拒绝「0.0.1-pre.1a」"    "0.0.1-pre.1a"
ck_reject "拒绝「abc」"             "abc"
ck_reject "拒绝「0.0.1-rc.01」"     "0.0.1-rc.01"

# 前提：上面这一串拒绝之后，沙盒还停在起始版本（否则下面的用例就不是在测改动）
ck "被拒的调用没有改到沙盒" "$(tr -d ' \t\r\n' < "$SB/VERSION")" "$OLD"

# ---------------------------------------------------------------------------
section "端到端：把四处都改到"
# ---------------------------------------------------------------------------
out="$(bash "$SB/scripts/version-bump.sh" "$NEW" 2>&1)"; rc=$?
ck "退出码" "$rc" "0"
ck_has "输出里说明改了哪几处" "$out" "已同步四处"

ck "VERSION"                    "$(tr -d ' \t\r\n' < "$SB/VERSION")"                  "$NEW"
ck "version.go 里 1 处"          "$(count_in "$SB/internal/version/version.go" "\"$NEW\"")" "1"
ck "package.json 里 1 处"        "$(count_in "$SB/web/package.json" "\"$NEW\"")"           "1"
ck "package-lock.json 里 2 处"   "$(count_in "$SB/web/package-lock.json" "\"$NEW\"")"      "2"

ck "version.go 已无旧值"    "$(count_in "$SB/internal/version/version.go" "\"$OLD\"")"  "0"
ck "package.json 已无旧值"  "$(count_in "$SB/web/package.json" "\"$OLD\"")"            "0"
ck "lock 文件已无旧值"      "$(count_in "$SB/web/package-lock.json" "\"$OLD\"")"       "0"

# 不带引号的历史版本号（注释里那条）必须原样留着 —— 改动范围只限"引号里的版本号"。
ck "注释里的历史版本号未被改动" \
  "$(count_in "$SB/internal/version/version.go" "历史：$OLD 之前")" "1"
# 依赖自身的 version 不能被误伤。
ck "依赖版本未被改动" "$(count_in "$SB/web/package-lock.json" "\"3.5.43\"")" "1"

# sed -i.bak 会在工作区留下 .bak；之前正是这个把 git status 搞脏了。
ck "没有留下 .bak 文件" "$(find "$SB" -name '*.bak' | wc -l | tr -d ' ')" "0"

# ---------------------------------------------------------------------------
section "幂等：同版本再跑一次"
# ---------------------------------------------------------------------------
before="$(cat "$SB/VERSION" "$SB/internal/version/version.go" "$SB/web/package.json" "$SB/web/package-lock.json" | cksum)"
out="$(bash "$SB/scripts/version-bump.sh" "$NEW" 2>&1)"; rc=$?
after="$(cat "$SB/VERSION" "$SB/internal/version/version.go" "$SB/web/package.json" "$SB/web/package-lock.json" | cksum)"

ck "退出码" "$rc" "0"
ck_has "提示无需改动" "$out" "无需改动"
ck "文件内容未变" "$after" "$before"

# ---------------------------------------------------------------------------
section "回退到旧版本"
# ---------------------------------------------------------------------------
out="$(bash "$SB/scripts/version-bump.sh" "$OLD" 2>&1)"; rc=$?
ck "退出码" "$rc" "0"
ck "VERSION" "$(tr -d ' \t\r\n' < "$SB/VERSION")" "$OLD"
ck "package-lock.json 回到 2 处" "$(count_in "$SB/web/package-lock.json" "\"$OLD\"")" "2"
ck "没有留下 .bak 文件" "$(find "$SB" -name '*.bak' | wc -l | tr -d ' ')" "0"

# ---------------------------------------------------------------------------
section "缺文件时必须报错，不能改一半"
# ---------------------------------------------------------------------------
mk_sandbox "$OLD" "web/package.json"
out="$(bash "$SB/scripts/version-bump.sh" "$NEW" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ]; then
  printf '  %s %-46s\n' "$(green PASS)" "缺 web/package.json 时报错"; PASS=$((PASS + 1))
else
  printf '  %s %-46s\n' "$(red FAIL)" "缺 web/package.json 时报错"; FAIL=$((FAIL + 1))
fi
ck_has "提示缺哪个文件" "$out" "web/package.json"
# 前置校验在读 VERSION 之前做完，所以 VERSION 不该被改动。
ck "VERSION 未被改动" "$(tr -d ' \t\r\n' < "$SB/VERSION")" "$OLD"

# ---------------------------------------------------------------------------
section "守卫：本测试没有碰过仓库里的文件"
# ---------------------------------------------------------------------------
ck "仓库四处文件的校验和未变" "$(repo_fingerprint)" "$REPO_BEFORE"

# ---------------------------------------------------------------------------
printf '\n通过 %d 项，失败 %d 项\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
