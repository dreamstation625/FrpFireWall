#!/usr/bin/env bash
#
# test-install.sh —— scripts/install.sh 的完整回归测试。
#
# 两段：
#   A. 纯函数：版本号解析 / 规范化 / 比较，并与 tools/versioncmp（Go 侧同一套语义）
#      逐条对照，防止两边实现漂移。
#   B. 端到端：起一个假 GitHub Releases 服务，用桩命令替换 systemctl / iptables /
#      install / uname / id，在受控目录里真的跑一遍
#      安装 → 升级 → 回滚 → 卸载 的完整流程。
#
# 全程不碰真实的 /usr/local/bin、/etc/systemd/system、iptables。
#
# ---------------------------------------------------------------------------
# 验证边界（重要，别把这里的 PASS 当成防火墙功能没问题）
# ---------------------------------------------------------------------------
# 本节测的是「一键脚本」，不是「防火墙」。脚本里跟防火墙沾边的部分，这里
# 用的是桩命令（见下面「桩命令」一节），所以只能验证到：
#
#     脚本有没有在正确的时机、用正确的命令行形状去调用 iptables / nft。
#
# 验证不到、也不打算在这里验证的：
#   * 规则是否真的从内核里消失了（netfilter 表、链、跳转的真实状态）
#   * 封禁/解封是否真的生效，以及与其他防火墙工具（ufw / firewalld / Docker
#     的 nft 规则）的相互影响
#   * iptables 与 nft 两个后端在真实内核上的行为差异
#   * 服务重启后规则是否被正确恢复
#
# 这些属于程序自身的功能测试，必须在**真实的 Linux 内核**上做 —— 用真的
# iptables / nft 起容器或虚拟机跑，而不是用桩。桩命令返回的是脚本作者
# 预先写好的答案，它永远会「通过」，那只能证明调用发生了。
#
# 因此：本文件在 Windows 上（MSYS / Git Bash）可以跑，因为桩命令不依赖
# Linux 内核；但 Windows 上的 PASS **不代表**防火墙功能可用。
#
# 用法： bash testdata/test-install.sh
#
set -u

cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
INSTALL_SH="$ROOT/scripts/install.sh"

PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m' "$1"; }
green() { printf '\033[32m%s\033[0m' "$1"; }

section() { printf '\n########## %s ##########\n' "$*"; }

ck() { # 描述 实际 期望
  if [ "$2" = "$3" ]; then
    printf '  %s %-50s %s\n' "$(green PASS)" "$1" "$2"; PASS=$((PASS + 1))
  else
    printf '  %s %-50s got=%s want=%s\n' "$(red FAIL)" "$1" "$2" "$3"; FAIL=$((FAIL + 1))
  fi
}

ck_has() { # 描述 文本 关键词
  case "$2" in
    *"$3"*) printf '  %s %-50s 命中「%s」\n' "$(green PASS)" "$1" "$3"; PASS=$((PASS + 1)) ;;
    *)      printf '  %s %-50s 未命中「%s」\n' "$(red FAIL)" "$1" "$3"
            printf '%s\n' "$(printf '%s' "$2" | tail -6 | sed 's/^/          | /')"
            FAIL=$((FAIL + 1)) ;;
  esac
}

# ---------------------------------------------------------------------------
# 路径与临时目录
# ---------------------------------------------------------------------------

# 刻意不用 ${TMPDIR}：Windows 上它是 C:\Users\...\Temp 这种形态，
# 塞进 PATH 之后「C:」里的冒号会把 PATH 切成两段，桩命令就再也搜不到了。
if [ ! -d /tmp ]; then
  printf '缺少 /tmp，无法进行端到端测试\n' >&2
  exit 1
fi
WORK="$(mktemp -d /tmp/frpfirewall-e2e.XXXXXX)"
STUB="$WORK/stub"
REL="$WORK/release"
PREFIX="$WORK/usr/local/bin"
DATA="$WORK/var/lib/frpfirewall"
UNITDIR="$WORK/etc/systemd/system"
SYSD_STATE="$WORK/systemd.state"
LOG="$WORK/calls.log"
OUT="$WORK/out.txt"
ERR="$WORK/err.txt"
CMPDIR="$WORK/cmp"

mkdir -p "$STUB" "$REL" "$CMPDIR" "$WORK/tmp"
# 真实系统上 /etc/systemd/system 必然存在，测试里得自己铺出来
mkdir -p "$UNITDIR"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null; fi
  # 清理失败不能反过来把测试判成失败：某些环境会拦截 rm -rf（回收站不可用、
  # 只读挂载、受限的 /tmp），那是环境的事，不是被测代码的事。
  rm -rf "$WORK" 2>/dev/null || true
  return 0
}
trap cleanup EXIT

# ===========================================================================
# A. 纯函数与 Go 侧一致性
# ===========================================================================

section "A. 版本号解析 / 规范化 / 比较"

if bash -n "$INSTALL_SH"; then
  printf '  %s %-50s\n' "$(green PASS)" "install.sh 语法检查通过"; PASS=$((PASS + 1))
else
  printf '  %s %-50s\n' "$(red FAIL)" "install.sh 语法检查未通过"; FAIL=$((FAIL + 1))
fi

run_pure() { FRPFW_LIB_ONLY=1 bash -c "source '$INSTALL_SH'; $1"; }

ck "vnorm 标准写法保持不变"     "$(run_pure 'vnorm 0.0.1')"          "0.0.1"
ck "vnorm 去掉 v 前缀"          "$(run_pure 'vnorm v0.0.1')"         "0.0.1"
ck "vnorm 预发布序号补零"       "$(run_pure 'vnorm 0.0.1-pre.1')"    "0.0.1-pre.01"
ck "vnorm 剥离 +build 元数据"   "$(run_pure 'vnorm 0.0.1+build.7')"  "0.0.1"
ck "vparse 正式版 pre 段为 0"   "$(run_pure 'vparse 0.0.1')"         "0 0 1 0"
ck "vparse 预发布序号"          "$(run_pure 'vparse v0.0.1-pre.99')" "0 0 1 99"
ck "vcmp 同号正式版大于预发布"   "$(run_pure 'vcmp 0.0.1 0.0.1-pre.99')" "1"
ck "vcmp 预发布小于同号正式版"   "$(run_pure 'vcmp 0.0.1-pre.99 0.0.1')" "-1"
ck "vcmp 等价写法判等"          "$(run_pure 'vcmp 0.0.1 v0.0.1')"    "0"
ck "vcmp 预发布序号数值比较"     "$(run_pure 'vcmp 0.0.1-pre.02 0.0.1-pre.10')" "-1"
ck "vcmp 按数值而非字符串（10>9）" "$(run_pure 'vcmp 0.0.10 0.0.9')"  "1"
ck "vcmp 前导零不影响数值"       "$(run_pure 'vcmp 0.0.09 0.0.10')"   "-1"
ck "vcmp 次版本优先于修订号"     "$(run_pure 'vcmp 0.1.0 0.0.99')"    "1"

for bad in "0.0.1-pre.0" "0.0.1-rc.1" "0.0.1-dev" "1.2" "1.2.3.4" "0..1" "x.y.z" "-pre.1" "1.2.-3"; do
  if run_pure "vparse '$bad'" >/dev/null 2>&1; then
    printf '  %s %-50s 却被接受了\n' "$(red FAIL)" "拒绝非法输入「$bad」"; FAIL=$((FAIL + 1))
  else
    printf '  %s %-50s\n' "$(green PASS)" "拒绝非法输入「$bad」"; PASS=$((PASS + 1))
  fi
done

section "A2. 监听地址校验与回环判断"

# 监听地址写错的后果是 systemd 直接拒绝启动，所以在安装前就拦掉，
# 别等 daemon-reload 才报错。
for good in "0.0.0.0:7930" "127.0.0.1:7930" "192.168.1.10:8080" "[::]:7930"; do
  if run_pure "valid_listen '$good'" >/dev/null 2>&1; then
    printf '  %s %-50s\n' "$(green PASS)" "接受监听地址「$good」"; PASS=$((PASS + 1))
  else
    printf '  %s %-50s 却被拒绝\n' "$(red FAIL)" "接受监听地址「$good」"; FAIL=$((FAIL + 1))
  fi
done

# 前导零单独测：bash 的 [ -lt ] 会把 08 当八进制而报错，valid_listen 里
# 用 10# 显式按十进制解释，这条就是钉住它的。
if run_pure "valid_listen '0.0.0.0:07930'" >/dev/null 2>&1; then
  printf '  %s %-50s\n' "$(green PASS)" "接受带前导零的端口「07930」"; PASS=$((PASS + 1))
else
  printf '  %s %-50s 却被拒绝\n' "$(red FAIL)" "接受带前导零的端口「07930」"; FAIL=$((FAIL + 1))
fi

for bad_addr in "" "7930" "0.0.0.0" "0.0.0.0:" "0.0.0.0:0" "0.0.0.0:65536" "0.0.0.0:abc"; do
  if run_pure "valid_listen '$bad_addr'" >/dev/null 2>&1; then
    printf '  %s %-50s 却被接受\n' "$(red FAIL)" "拒绝非法监听地址「$bad_addr」"; FAIL=$((FAIL + 1))
  else
    printf '  %s %-50s\n' "$(green PASS)" "拒绝非法监听地址「$bad_addr」"; PASS=$((PASS + 1))
  fi
done

# 这个判断决定装完是提示"直接打开"还是"先想办法进去"，说反了就会重演
# 「照着提示访问却连不上」那次事故。
ck "0.0.0.0 不算回环"  "$(run_pure 'listen_is_loopback 0.0.0.0:7930 && echo y || echo n')"     "n"
ck "127.0.0.1 算回环"  "$(run_pure 'listen_is_loopback 127.0.0.1:7930 && echo y || echo n')"   "y"
ck "localhost 算回环"  "$(run_pure 'listen_is_loopback localhost:7930 && echo y || echo n')"   "y"
ck "内网地址不算回环"  "$(run_pure 'listen_is_loopback 192.168.1.10:7930 && echo y || echo n')" "n"

section "A3. 与 tools/versioncmp（Go 侧）逐条对照"

# install.sh 里的比较逻辑必须和程序内 internal/version 完全一致，否则会出现
# 「面板提示有更新、一键脚本却说已是最新」这种自相矛盾。这里把同一批用例
# 同时喂给两边，逐条比对判定结果。
VERSIONCMP="$CMPDIR/versioncmp"
GO_AVAILABLE=1
if ! go build -o "$VERSIONCMP" ./tools/versioncmp >/dev/null 2>&1; then
  GO_AVAILABLE=0
fi

if [ "$GO_AVAILABLE" -eq 0 ]; then
  printf '  %s %-50s\n' "$(red FAIL)" "无法构建 tools/versioncmp，跳过对照"; FAIL=$((FAIL + 1))
else
  # go 侧拿不到裸的 Compare，但守门工具的输出等价于 (a > max(b))。
  # 两个方向都跑一次就能把 >、<、= 区分开。
  go_cmp() {
    local ab ba
    printf '%s\n' "$2" > "$CMPDIR/base.txt"
    ab="$("$VERSIONCMP" -candidate "$1" -existing "$CMPDIR/base.txt" 2>/dev/null | sed -n 's/^publish=//p')"
    printf '%s\n' "$1" > "$CMPDIR/base.txt"
    ba="$("$VERSIONCMP" -candidate "$2" -existing "$CMPDIR/base.txt" 2>/dev/null | sed -n 's/^publish=//p')"
    if [ "$ab" = "true" ]; then printf '1\n'
    elif [ "$ba" = "true" ]; then printf -- '-1\n'
    else printf '0\n'; fi
  }

  CASES="
0.0.1|0.0.1
0.0.1|v0.0.1
0.0.1|0.0.1-pre.01
0.0.1-pre.01|0.0.1
0.0.1-pre.01|0.0.1-pre.02
0.0.1-pre.99|0.0.1
0.0.2|0.0.1
0.0.1|0.0.2
0.1.0|0.0.99
0.0.10|0.0.9
0.0.9|0.0.10
1.0.0|0.99.99
0.0.1-pre.02|0.0.1-pre.10
0.0.2-pre.01|0.0.1
0.0.1|0.0.2-pre.01
"
  while IFS='|' read -r a b; do
    [ -n "$a" ] || continue
    lhs="$(run_pure "vcmp '$a' '$b'")"
    rhs="$(go_cmp "$a" "$b")"
    if [ "$lhs" = "$rhs" ]; then
      printf '  %s %-50s %s\n' "$(green PASS)" "vcmp $a vs $b" "$lhs"; PASS=$((PASS + 1))
    else
      printf '  %s %-50s bash=%s go=%s\n' "$(red FAIL)" "vcmp $a vs $b" "$lhs" "$rhs"
      FAIL=$((FAIL + 1))
    fi
  done <<< "$CASES"

  for bad in "0.0.1-rc.1" "1.2" "0.0.1-pre.0"; do
    printf '' > "$CMPDIR/base.txt"
    if "$VERSIONCMP" -candidate "$bad" -existing "$CMPDIR/base.txt" >/dev/null 2>&1; then
      go_ok=1
    else
      go_ok=0
    fi
    if run_pure "vparse '$bad'" >/dev/null 2>&1; then bash_ok=1; else bash_ok=0; fi
    ck "两边都拒绝「$bad」" "$bash_ok/$go_ok" "0/0"
  done
fi

# ===========================================================================
# 桩命令
# ===========================================================================
# 全部记到同一个日志里，这样可以断言调用顺序（例如「先停服务再清规则」）。

cat > "$STUB/systemctl" <<'STUB'
#!/usr/bin/env bash
echo "systemctl $*" >> "${FAKE_LOG:-/dev/null}"
case "${1-}" in
  is-active)
    [ "$(cat "${FAKE_SYSD_STATE:?}" 2>/dev/null)" = "active" ] && exit 0
    exit 3 ;;
  start|restart)
    # 模拟「新版本起不来」：假二进制里带 FAILSTART 标记就判定启动失败
    if [ -f "${FAKE_PREFIX:?}/frpfirewall" ] && grep -q FAILSTART "${FAKE_PREFIX}/frpfirewall" 2>/dev/null; then
      echo failed > "$FAKE_SYSD_STATE"; exit 1
    fi
    echo active > "$FAKE_SYSD_STATE"; exit 0 ;;
  stop) echo inactive > "$FAKE_SYSD_STATE"; exit 0 ;;
  *) exit 0 ;;
esac
STUB

cat > "$STUB/uname" <<'STUB'
#!/usr/bin/env bash
case "${1-}" in
  -m) echo "${FAKE_ARCH:-x86_64}" ;;
  *)  echo Linux ;;
esac
STUB

cat > "$STUB/id" <<'STUB'
#!/usr/bin/env bash
if [ "${1-}" = "-u" ]; then echo 0; else echo "uid=0(root) gid=0(root) groups=0(root)"; fi
STUB

cat > "$STUB/journalctl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

# 真实的 install 在非 root 下会因 -o/-g 失败（Windows 上根本没有 root 用户），
# 这里换成只做「建目录 / 按权限复制」的最简实现。
cat > "$STUB/install" <<'STUB'
#!/usr/bin/env bash
mode=0755
makedir=0
files=()
while [ $# -gt 0 ]; do
  case "$1" in
    -d)     makedir=1; shift ;;
    -m)     mode="$2"; shift 2 ;;
    -o|-g)  shift 2 ;;
    -*)     shift ;;
    *)      files+=("$1"); shift ;;
  esac
done
if [ "$makedir" -eq 1 ]; then
  for d in "${files[@]}"; do mkdir -p "$d" && chmod "$mode" "$d" 2>/dev/null; done
  exit 0
fi
cp "${files[0]}" "${files[1]}" && chmod "$mode" "${files[1]}"
STUB

# iptables：-C 失败（链上还没有跳转）、-S 成功（假装链存在），
# 这样救援脚本会走完整的「摘跳转 → 清空 → 删链」路径。
#
# 注意这只是"假装"：桩命令不去读内核，它按上面的规则直接返回预设答案。
# 本节所有跟内核规则有关的断言，验证的都是**脚本发了什么命令**，
# 而不是**内核状态变成什么样**。理由见文件开头的「验证边界」。
for name in iptables ip6tables; do
  cat > "$STUB/$name" <<STUB
#!/usr/bin/env bash
echo "$name \$*" >> "\${FAKE_LOG:-/dev/null}"
for a in "\$@"; do
  case "\$a" in
    -C) exit 1 ;;
    -S) echo "-N FRPFIREWALL_BLACK"; exit 0 ;;
  esac
done
exit 0
STUB
done

cat > "$STUB/nft" <<'STUB'
#!/usr/bin/env bash
echo "nft $*" >> "${FAKE_LOG:-/dev/null}"
exit 0
STUB

chmod 0755 "$STUB"/*

# ===========================================================================
# 假发布
# ===========================================================================

make_release() { # make_release <tag> <version> [failstart]
  local tag="$1" ver="$2" bad="${3-}"
  local d="$REL/$tag"
  mkdir -p "$d"

  {
    printf '#!/usr/bin/env bash\n'
    if [ -n "$bad" ]; then printf '# FAILSTART\n'; fi
    printf '# 假二进制，仅供端到端测试，不会真的做任何事\n'
    printf 'echo "FrpFireWall %s (commit fake123, built 2026-01-01T00:00:00Z)"\n' "$ver"
  } > "$d/frpfirewall-linux-amd64"
  cp "$d/frpfirewall-linux-amd64" "$d/frpfirewall-linux-arm64"

  cp "$ROOT/scripts/frpfirewall-panic.sh" "$d/frpfirewall-panic.sh"
  cp "$ROOT/scripts/install.sh"           "$d/install.sh"

  cat > "$d/frpfirewall.service" <<EOF
[Unit]
Description=frpfirewall (fake, e2e)
[Service]
ExecStart=$PREFIX/frpfirewall -data $DATA
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  chmod 0755 "$d/frpfirewall-linux-amd64" "$d/frpfirewall-linux-arm64" \
             "$d/frpfirewall-panic.sh" "$d/install.sh"
  ( cd "$d" && sha256sum \
      frpfirewall-linux-amd64 frpfirewall-linux-arm64 \
      frpfirewall-panic.sh frpfirewall.service install.sh > sha256sums.txt )
}

# 重建 latest 指针与 Releases API 应答。latest 为空表示「只有预发布」。
refresh_index() { # refresh_index [latest-tag]
  local latest="${1-}" d tag first=1
  if [ -n "$latest" ]; then printf '%s\n' "$latest" > "$REL/latest"; else rm -f "$REL/latest"; fi

  {
    printf '['
    for d in "$REL"/v*; do
      [ -d "$d" ] || continue
      tag="$(basename "$d")"
      [ "$first" -eq 1 ] || printf ','
      first=0
      case "$tag" in *-pre.*) pre=true ;; *) pre=false ;; esac
      printf '{"tag_name":"%s","prerelease":%s,"draft":false,"name":"%s"}' "$tag" "$pre" "$tag"
    done
    printf ']\n'
  } > "$REL/releases.json"
}

# ===========================================================================
# 跑脚本
# ===========================================================================

run_sh() {
  : > "$OUT"; : > "$ERR"

  # 默认把 --data-dir 指到受控目录；但调用方自己传了 --data-dir 时要让位，
  # 否则为了测护栏而传的路径会被这里追加的参数覆盖掉。
  local extra=()
  case " $* " in
    *" --data-dir "*) ;;
    *) extra+=(--data-dir "$DATA") ;;
  esac

  # TMPDIR 收进工作目录：脚本内部用 mktemp 建临时目录，不指定的话会落到
  # 系统 Temp（Windows 上是 C:\...\Temp，还会被本机安全删除钩子拦下来）。
  # 让测试产生的所有临时文件都待在自己能收拾的地方。
  env PATH="$STUB:$PATH" \
      TMPDIR="$WORK/tmp" \
      FAKE_SYSD_STATE="$SYSD_STATE" \
      FAKE_PREFIX="$PREFIX" \
      FAKE_LOG="$LOG" \
      FRPFW_REPO="test/fake" \
      no_proxy="127.0.0.1,localhost" NO_PROXY="127.0.0.1,localhost" \
      bash "$INSTALL_SH" "$@" \
      --prefix "$PREFIX" --unit-dir "$UNITDIR" \
      "${extra[@]}" \
      --base-url "$BASE" --api-url "$API" -y > "$OUT" 2> "$ERR"
}

all_output() { cat "$OUT" "$ERR"; }

installed_ver() {
  [ -x "$PREFIX/frpfirewall" ] || return 1
  "$PREFIX/frpfirewall" -version 2>/dev/null | awk 'NR==1{print $2}'
}

exists() { [ -e "$1" ] && echo yes || echo no; }

# ===========================================================================
# 起假 Release 服务
# ===========================================================================

echo
echo "正在准备端到端测试环境…"

make_release v0.0.1-pre.01 0.0.1-pre.01
refresh_index ""     # 此时还没有正式版

python3 "$ROOT/testdata/fake-release-server.py" --root "$REL" \
  > "$WORK/port.txt" 2> "$WORK/server.log" &
SERVER_PID=$!

PORT=""
for _ in $(seq 1 100); do
  PORT="$(head -1 "$WORK/port.txt" 2>/dev/null | tr -d '\r\n')"
  [ -n "$PORT" ] && break
  sleep 0.1
done

if [ -z "$PORT" ]; then
  printf '%s 假 Release 服务未能启动：\n' "$(red FAIL)"
  cat "$WORK/server.log"
  exit 1
fi
BASE="http://127.0.0.1:$PORT/releases"
API="http://127.0.0.1:$PORT"

# 先确认假服务自身是通的（含 no_proxy 是否真的绕开了本机代理）
CODE="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' \
  "$BASE/download/v0.0.1-pre.01/sha256sums.txt" 2>/dev/null || echo 000)"
if [ "$CODE" != "200" ]; then
  printf '%s 假服务不可用（http %s），检查 no_proxy 是否生效\n' "$(red FAIL)" "$CODE"
  cat "$WORK/server.log"
  exit 1
fi
printf '  假 Release 服务已就绪：%s\n' "$BASE"

# ===========================================================================
# B. 端到端
# ===========================================================================

section "B1. 只有预发布版时（仓库当前就是这个状态）"

run_sh status
ck "status 退出码" "$?" "0"
ck_has "status 报未安装" "$(all_output)" "未检测到"
ck_has "status 说明还没有正式版" "$(all_output)" "还没有正式版"

run_sh install
ck "默认只认正式版 → 拒绝安装" "$?" "1"
ck_has "给出了改用 --pre 的提示" "$(all_output)" "--pre"

run_sh update
ck "未安装时 update 报错" "$?" "1"
ck_has "提示改用 install" "$(all_output)" "install"

run_sh install --pre
ck "install --pre 成功" "$?" "0"
ck "装上的版本" "$(installed_ver)" "0.0.1-pre.01"
ck "服务已 active" "$(cat "$SYSD_STATE" 2>/dev/null)" "active"
ck "systemd 单元已写入" "$(exists "$UNITDIR/frpfirewall.service")" "yes"
ck "救援脚本已装到 PREFIX" "$(exists "$PREFIX/frpfirewall-panic")" "yes"
ck "数据目录已建" "$(exists "$DATA")" "yes"
ck "三个文件都通过了 sha256 校验" "$(grep -c 'sha256 ok' "$OUT")" "3"
ck "没有留下 .prev" "$(exists "$PREFIX/frpfirewall.prev")" "no"

section "B2. 发布正式版后升级（pre → 正式版）"

make_release v0.0.1 0.0.1
refresh_index v0.0.1

run_sh status --check
ck "status --check 有更新 → 退出码 10" "$?" "10"
ck_has "status 指出有新版本" "$(all_output)" "有新版本"

run_sh update
ck "update 成功" "$?" "0"
ck "升到 0.0.1" "$(installed_ver)" "0.0.1"
ck "服务仍 active" "$(cat "$SYSD_STATE")" "active"

run_sh update --dry-run
ck "已是新版时 dry-run 退出码" "$?" "0"
ck_has "dry-run 提示已是最新" "$(all_output)" "已是最新"

run_sh update
ck "重复 update 幂等" "$?" "0"
ck_has "重复 update 提示已是最新" "$(all_output)" "已是最新"

run_sh status --check
ck "无更新时 status --check 退出码" "$?" "0"

section "B3. 降级防护"

run_sh install -v 0.0.1-pre.01
ck "默认拒绝降级" "$?" "1"
ck_has "提示需要 --force" "$(all_output)" "--force"
ck "版本没被改动" "$(installed_ver)" "0.0.1"

run_sh install -v 0.0.1-pre.01 --force
ck "加 --force 后允许降级" "$?" "0"
ck "已降级" "$(installed_ver)" "0.0.1-pre.01"

# 这一条同时验证了「预发布版用户默认更新会走到正式版」，
# 与面板内检查更新的规则一致。
run_sh update
ck "降级后 update 升回正式版" "$?" "0"
ck "回到 0.0.1" "$(installed_ver)" "0.0.1"

section "B4. dry-run 不做任何改动"

run_sh install --dry-run -v 0.0.2
ck "dry-run 退出码" "$?" "0"
ck_has "dry-run 打印下载地址" "$(all_output)" "v0.0.2/frpfirewall-linux-amd64"
ck_has "dry-run 声明不做改动" "$(all_output)" "不会做任何改动"
ck "dry-run 后版本不变" "$(installed_ver)" "0.0.1"

section "B5. 正常升级"

make_release v0.0.2 0.0.2
refresh_index v0.0.2

run_sh update
ck "升级到 0.0.2" "$?" "0"
ck "版本已是 0.0.2" "$(installed_ver)" "0.0.2"
ck "升级成功后 .prev 已清理" "$(exists "$PREFIX/frpfirewall.prev")" "no"

section "B6. 新版本起不来 → 自动回滚"

make_release v0.0.3 0.0.3 FAILSTART
refresh_index v0.0.3

run_sh update
ck "启动失败时退出码非零" "$?" "1"
ck_has "提示已回滚" "$(all_output)" "已回滚"
ck_has "指出了出问题的版本" "$(all_output)" "0.0.3"
ck "回滚后仍是可用版本 0.0.2" "$(installed_ver)" "0.0.2"
ck "回滚后服务 active" "$(cat "$SYSD_STATE")" "active"
ck "回滚后 .prev 已消费掉" "$(exists "$PREFIX/frpfirewall.prev")" "no"

section "B7. 校验和不匹配必须中止"

make_release v0.0.4 0.0.4
refresh_index v0.0.4
# 造完校验和之后再篡改二进制，模拟传输损坏 / 中间人改包
printf '\n# 篡改\n' >> "$REL/v0.0.4/frpfirewall-linux-amd64"

run_sh update
ck "校验失败时退出码非零" "$?" "1"
ck_has "报出校验和不匹配" "$(all_output)" "校验和不匹配"
ck "校验失败没有改动已装版本" "$(installed_ver)" "0.0.2"

# 修回去，后面的用例还要用这个发布
make_release v0.0.4 0.0.4
refresh_index v0.0.4
run_sh update
ck "修复后能正常升级到 0.0.4" "$?" "0"
ck "版本已是 0.0.4" "$(installed_ver)" "0.0.4"

section "B8. 卸载"

: > "$LOG"
printf 'keepme\n' > "$DATA/keep.txt"
run_sh uninstall

ck "卸载退出码" "$?" "0"
ck "二进制已删除" "$(exists "$PREFIX/frpfirewall")" "no"
ck "救援脚本已删除" "$(exists "$PREFIX/frpfirewall-panic")" "no"
ck "systemd 单元已删除" "$(exists "$UNITDIR/frpfirewall.service")" "no"
ck "数据目录被保留" "$(exists "$DATA/keep.txt")" "yes"
ck_has "提示数据目录位置" "$(all_output)" "$DATA"
ck_has "提醒清理 frps.toml" "$(all_output)" "frps.toml"

# ---------------------------------------------------------------------------
# 下面这几条断言只覆盖「调用」层面，不覆盖「效果」层面。
#
# iptables / ip6tables / nft 在这里是桩命令（见文件开头「桩命令」一节），
# 它们把收到的参数原样记进 "$LOG" 就返回成功。所以这里能证明的是：
#   * 卸载时是先停服务、后动内核规则（顺序错了进程会再 reconcile 回来）
#   * 救援脚本确实对预期的链名发起了 -F / -X
# 证明不了的是「内核里的链真的没了」—— 桩命令不会去读内核，它只会点头。
# 真要验证效果，得在 Linux 上用真实 iptables/nft 跑一遍。
# ---------------------------------------------------------------------------

# 顺序很关键：进程还在跑的话会在下一次 reconcile 把规则重新下发
STOP_LINE="$(grep -n '^systemctl stop' "$LOG" | head -1 | cut -d: -f1)"
IPT_LINE="$(grep -n '^iptables' "$LOG" | head -1 | cut -d: -f1)"
if [ -n "$STOP_LINE" ] && [ -n "$IPT_LINE" ] && [ "$STOP_LINE" -lt "$IPT_LINE" ]; then
  printf '  %s %-50s stop@%s < iptables@%s\n' \
    "$(green PASS)" "先停服务、后动内核规则（调用顺序）" "$STOP_LINE" "$IPT_LINE"; PASS=$((PASS + 1))
else
  printf '  %s %-50s stop@%s iptables@%s\n' \
    "$(red FAIL)" "先停服务、后动内核规则（调用顺序）" "${STOP_LINE:-无}" "${IPT_LINE:-无}"; FAIL=$((FAIL + 1))
fi
ck "救援脚本发起了删 ipv4 链（桩，不验效果）" "$(grep -c 'iptables -w -F FRPFIREWALL_BLACK' "$LOG")" "1"
ck "救援脚本发起了删 ipv6 链（桩，不验效果）" "$(grep -c 'ip6tables -w -X FRPFIREWALL_GUARD' "$LOG")" "1"

run_sh uninstall
ck "重复卸载仍然成功" "$?" "0"

section "B9. --purge 的护栏与正常路径"

# 铺一个「已安装」的状态，好走到 --purge 那一步
mkdir -p "$DATA" "$PREFIX"
printf 'x' > "$DATA/frpfirewall.db"
cp "$ROOT/scripts/install.sh" "$PREFIX/frpfirewall"

# 护栏一：指向一个非空、且不含本程序数据库的目录（模拟 --data-dir 手滑）
mkdir -p "$WORK/var/lib/someone-elses-data"
printf 'important\n' > "$WORK/var/lib/someone-elses-data/notes.txt"
run_sh uninstall --purge --data-dir "$WORK/var/lib/someone-elses-data"
ck "拒绝删除不相干的目录" "$?" "1"
ck_has "给出了拒绝理由" "$(all_output)" "不是本程序的数据目录"
ck "该目录仍然健在" "$(exists "$WORK/var/lib/someone-elses-data/notes.txt")" "yes"
ck "拒绝时没有先删掉应用" "$(exists "$PREFIX/frpfirewall")" "yes"

# 护栏二：指向系统目录
run_sh uninstall --purge --data-dir /etc
ck "拒绝删除 /etc" "$?" "1"
ck_has "指出是系统目录" "$(all_output)" "系统目录"

# 护栏三：根目录
run_sh uninstall --purge --data-dir /
ck "拒绝删除 /" "$?" "1"

# 正常路径：数据目录里有本程序的数据库 → 允许删
run_sh uninstall --purge
ck "purge 退出码" "$?" "0"
ck "数据目录已删除" "$(exists "$DATA")" "no"
ck_has "明说数据已删" "$(all_output)" "数据目录已删除"

section "B10. 参数与用法"

run_sh --help
ck "--help 退出码" "$?" "0"
ck_has "帮助里有三种动作" "$(all_output)" "uninstall"
ck_has "帮助里说明了镜像用法" "$(all_output)" "--mirror"

run_sh 未知动作
ck "未知动作退出码 2" "$?" "2"

run_sh install --no-such-flag
ck "未知选项退出码 2" "$?" "2"

run_sh --uninstall
ck "旧的 --uninstall 写法仍可用" "$?" "0"

run_sh --pre status
ck "动作可放在选项之后" "$?" "0"

section "B11. --listen 与 systemd 监听覆盖"

DROPDIR="$UNITDIR/frpfirewall.service.d"
DROPIN="$DROPDIR/10-listen.conf"

# 前面 B8/B9 已经把东西卸干净了，这里重新装一个来测覆盖文件
make_release v0.0.5 0.0.5
refresh_index v0.0.5

run_sh install
ck "重新装好 0.0.5" "$?" "0"
ck_has "提示里给出默认监听地址" "$(all_output)" "0.0.0.0:7930"
ck "未指定 --listen 时不生成覆盖文件" "$(exists "$DROPIN")" "no"

run_sh install --force --listen 0.0.0.0:8888
ck "--listen 安装成功" "$?" "0"
ck "覆盖文件已生成" "$(exists "$DROPIN")" "yes"
ck "覆盖文件带了指定地址" "$(grep -c -e '-listen 0.0.0.0:8888' "$DROPIN")" "1"
# ExecStart= 那行不能省：systemd 的 ExecStart 是追加语义，不清空会变成两条
# 启动命令并存，抢同一个端口，服务直接起不来。
ck "ExecStart 先清空再重设" "$(grep -c '^ExecStart=$' "$DROPIN")" "1"

# 不带 --listen 重装时**保留**覆盖文件。
# 删掉它听起来更"干净"，但库里可能存着一行老默认值 127.0.0.1:7930，
# 覆盖文件一没，服务就退回只监听回环 —— 人进不去面板，也就改不回来。
run_sh install --force
ck "重装不带 --listen 时保留旧覆盖" "$?" "0"
ck "覆盖文件仍在" "$(exists "$DROPIN")" "yes"
ck_has "提示里说明它仍在生效" "$(all_output)" "仍然会盖住面板里的监听设置"
ck_has "并给出让它让位的做法" "$(all_output)" "rm -f $DROPIN"

# 写错的地址要在动手之前就拦掉，否则是 systemd 起不来才报错
run_sh install --listen 0.0.0.0
ck "非法 --listen 退出码 2" "$?" "2"
ck_has "说明了正确格式" "$(all_output)" "host:port"
ck "校验失败时不动已有的覆盖文件" "$(exists "$DROPIN")" "yes"

# "已是最新版本"这条提前返回的路也必须认 --listen：想改监听地址的人多半是
# 面板打不开了，版本没变不代表这个参数可以丢掉。
run_sh update --listen 0.0.0.0:9999
ck "已是最新时 --listen 仍然生效" "$?" "0"
ck "覆盖文件已更新为新地址" "$(grep -c -e '-listen 0.0.0.0:9999' "$DROPIN")" "1"
ck_has "并告知监听地址已设" "$(all_output)" "监听地址已设为 0.0.0.0:9999"

# 卸载是显式意图，这时才把覆盖文件一并收走，不留一个指向已删二进制的启动参数
run_sh uninstall
ck "卸载成功" "$?" "0"
ck "卸载时收走监听覆盖" "$(exists "$DROPIN")" "no"

# ===========================================================================
section "汇总"
echo
printf '通过 %d 项，失败 %d 项\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "存在失败项"
  exit 1
fi
echo "全部通过"
