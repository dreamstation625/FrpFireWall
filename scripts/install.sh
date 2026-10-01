#!/usr/bin/env bash
#
# frpfirewall 一键脚本 —— 在线安装 / 升级 / 卸载（Debian / Ubuntu 系 + systemd）
#
# 在线用法：
#   # 安装最新正式版
#   curl -fsSL https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh | sudo bash
#
#   # 升级到最新正式版
#   curl -fsSL .../install.sh | sudo bash -s -- update
#
#   # 卸载（保留数据目录）
#   curl -fsSL .../install.sh | sudo bash -s -- uninstall
#
#   # 卸载并删除数据目录（封禁记录、白名单、面板密码都会没）
#   curl -fsSL .../install.sh | sudo bash -s -- uninstall --purge
#
# 也可以先把脚本存下来再执行（推荐：可以先读一遍）：
#   curl -fsSLO .../install.sh && less install.sh && sudo bash install.sh update
#
# 离线用法（把二进制和服务单元放到同一目录）：
#   sudo ./install.sh -b ./frpfirewall-linux-amd64
#
# 下载慢的话加加速前缀（不加就直连 GitHub）：
#   curl -fsSL ... | sudo bash -s -- install --mirror https://ghfast.top/
#
# ---------------------------------------------------------------------------
# 设计要点
#
# · 动作与选项分离：第一个位置参数是动作（install / update / uninstall /
#   status），缺省是 install。老的 --uninstall 仍然可用。
#
# · 下载的每个文件都用发布自带的 sha256sums.txt 校验。二进制是硬性要求，
#   校验和文件里没有条目就直接失败；辅助文件（服务单元、救援脚本）缺条目
#   只警告 —— 早期发布的校验和只覆盖了二进制，那种旧版本仍应可装。
#
# · 升级是先下载、校验、再原子替换，最后才重启。替换前把当前二进制另存为
#   .prev，新版本起不来就换回去再重启一次 —— 防火墙程序升级失败会直接
#   掉防护，不能只留一句「启动失败」就撒手。
#
# · 版本比较只认 0.0.1（正式版）与 0.0.1-pre.NN（预发布）两种形态，语义与
#   程序内的 internal/version 完全一致（同号段正式版大于预发布版）。
#   两边的一致性由 testdata/test-install.sh 用同一批用例钉死。
#
# · 卸载默认保留数据目录，--purge 才删，且删除前有多重护栏。
# ---------------------------------------------------------------------------
set -euo pipefail

# ===========================================================================
# 常量
# ===========================================================================

# 仓库（可用环境变量覆盖，方便 fork 与自建镜像）
REPO="${FRPFW_REPO:-dreamstation625/FrpFireWall}"

GH_BASE="${FRPFW_GITHUB_BASE:-https://github.com}"
API_BASE_DEFAULT="${FRPFW_API_BASE:-https://api.github.com}"

DEFAULT_PREFIX="/usr/local/bin"
DEFAULT_DATA_DIR="/var/lib/frpfirewall"
DEFAULT_UNIT_DIR="/etc/systemd/system"
SERVICE="frpfirewall"

# 探测最新正式版用的探针文件：随便挑一个每个 release 都有的资产即可，
# 我们只要它的 302 跳转地址里的 tag。用 HEAD 请求，不落盘、不下 body。
PROBE_ASSET="frpfirewall-linux-amd64"

UA="frpfirewall-installer (+https://github.com/${REPO})"

# 退出码
EXIT_OK=0
EXIT_ERR=1
EXIT_USAGE=2
EXIT_HAS_UPDATE=10

# ===========================================================================
# 输出
# ===========================================================================

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; C_OFF=""
fi

log()  { printf '%s==>%s %s\n' "$C_GREEN" "$C_OFF" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_OFF" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit "$EXIT_ERR"; }
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }

# ===========================================================================
# 纯函数区：版本号解析 / 比较 / 规范化
#
# 语义必须与 internal/version/version.go 完全一致：
#   · 只接受 主.次.修订 三段非负整数，可带 v 前缀与 +build 元数据
#   · 预发布段只接受 -pre.<正整数>（pre.0 非法）
#   · 主次修订相同时，正式版大于预发布版（0.0.1 > 0.0.1-pre.99）
#
# 这一层不打印错误、不退出，只返回非零 —— 因为它经常跑在 $( ) 里，
# 那里的 exit 只会杀掉子 shell，调用方会误以为拿到了空值。
# ===========================================================================

# 解析版本号，成功时输出 "<主> <次> <修订> <预发布序号>"，序号 0 表示正式版。
vparse() {
  local raw="${1-}"

  # 去首尾空白（不用 xargs：它会吃掉引号与反斜杠）
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  raw="${raw%%+*}"          # 去掉 +build 元数据，它不参与比较
  raw="${raw#v}"            # git tag 常见的 v 前缀
  [ -n "$raw" ] || return 1

  local core="$raw" pre="" has_pre=0
  case "$raw" in
    *-*)
      core="${raw%%-*}"
      local rest="${raw#*-}"
      case "$rest" in
        pre.*) pre="${rest#pre.}"; has_pre=1 ;;
        *) return 1 ;;
      esac
      ;;
  esac

  local -a parts=()
  local IFS='.'
  read -r -a parts <<<"$core"
  [ "${#parts[@]}" -eq 3 ] || return 1

  local p
  for p in "${parts[@]}"; do
    # 空串单独判：`10#` 遇到空串会直接报错
    [ -n "$p" ] || return 1
    case "$p" in *[!0-9]*) return 1 ;; esac
  done

  local pre_num=0
  if [ "$has_pre" -eq 1 ]; then
    [ -n "$pre" ] || return 1
    case "$pre" in *[!0-9]*) return 1 ;; esac
    pre_num=$((10#$pre))
    # 序号 0 是「非预发布」的哨兵值，写 -pre.0 属于非法输入
    [ "$pre_num" -gt 0 ] || return 1
  fi

  printf '%d %d %d %d\n' \
    "$((10#${parts[0]}))" "$((10#${parts[1]}))" "$((10#${parts[2]}))" "$pre_num"
}

# 把版本号规范化成 0.0.1 / 0.0.1-pre.01 的标准写法（预发布序号补零）。
vnorm() {
  local parsed
  parsed="$(vparse "${1-}")" || return 1
  local -a a=()
  read -r -a a <<<"$parsed"
  if [ "${a[3]}" -eq 0 ]; then
    printf '%d.%d.%d\n' "${a[0]}" "${a[1]}" "${a[2]}"
  else
    printf '%d.%d.%d-pre.%02d\n' "${a[0]}" "${a[1]}" "${a[2]}" "${a[3]}"
  fi
}

# 比较两个版本号，输出 -1 / 0 / 1。任一无法解析则返回非零。
vcmp() {
  local pa pb
  pa="$(vparse "${1-}")" || return 1
  pb="$(vparse "${2-}")" || return 1

  local -a A=() B=()
  read -r -a A <<<"$pa"
  read -r -a B <<<"$pb"

  local i
  for i in 0 1 2; do
    if [ "${A[$i]}" -gt "${B[$i]}" ]; then printf '1\n'; return 0; fi
    if [ "${A[$i]}" -lt "${B[$i]}" ]; then printf -- '-1\n'; return 0; fi
  done

  # 主次修订相同：Pre=0 是正式版，比同号段的任何预发布都大
  local ap="${A[3]}" bp="${B[3]}"
  if [ "$ap" -eq 0 ] && [ "$bp" -eq 0 ]; then printf '0\n'; return 0; fi
  if [ "$ap" -eq 0 ]; then printf '1\n'; return 0; fi
  if [ "$bp" -eq 0 ]; then printf -- '-1\n'; return 0; fi
  if [ "$ap" -gt "$bp" ]; then printf '1\n'; return 0; fi
  if [ "$ap" -lt "$bp" ]; then printf -- '-1\n'; return 0; fi
  printf '0\n'
}

# 当前机器该下哪个二进制
varch() {
  case "$(uname -m)" in
    x86_64|amd64)  printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) return 1 ;;
  esac
}

# ===========================================================================
# 纯函数区到此结束。测试可以用 FRPFW_LIB_ONLY=1 source 本文件，
# 只加载上面的函数而不触发下面的任何动作。
# ===========================================================================
if [ "${FRPFW_LIB_ONLY:-0}" = "1" ]; then
  # 被 source 时（BASH_SOURCE 与 $0 不同）用 return 退出本文件；
  # 被直接执行时才 exit。不能写成 `return 0 || exit 0` —— 那在 source 场景下
  # return 成功，调用方剩下的语句就全被跳过了。
  if [ "${BASH_SOURCE[0]:-}" != "$0" ]; then
    return 0
  fi
  exit 0
fi

# ===========================================================================
# 运行期状态
# ===========================================================================

ACTION=""
PREFIX="$DEFAULT_PREFIX"
DATA_DIR="$DEFAULT_DATA_DIR"
UNIT_DIR="$DEFAULT_UNIT_DIR"
ASSUME_YES=0
DO_START=1
PURGE=0
FORCE=0
ALLOW_PRE=0
DRY_RUN=0
CHECK_ONLY=0
PIN_VERSION=""
BIN_SRC=""
OFFLINE=0
MIRROR="${FRPFW_MIRROR:-}"
RELEASES_BASE=""
API_BASE="$API_BASE_DEFAULT"
WORKDIR=""

UNIT_SRC=""
UNIT_MGR=""

# 脚本自身所在目录；从管道执行时为空。
# 这时不会有 .service / panic.sh 之类的同目录文件，全部走在线下载。
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || SCRIPT_DIR=""
fi

# EXIT trap。这里做错会让「安装成功」变成「退出码 1」，所以两条都不能少：
#   1. 先把进来的退出码记下来，出 trap 时原样还回去；
#   2. 清理动作自己失败必须吞掉 —— rm 遇到只读挂载、不可变属性（chattr +i）、
#      受限的 /tmp（容器、加固的系统）都会失败，但那跟这次安装成没成功
#      没有任何关系，不该由它来决定脚本的结论。
# 另外 set -e 在 trap 里照样生效，所以不能用 `[ … ] && rm` 这种链，也不能
# 让 rm 的失败码漏出去。
cleanup() {
  local rc=$?
  if [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR" ]; then
    rm -rf "$WORKDIR" 2>/dev/null || true
  fi
  return "$rc"
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
frpfirewall 一键脚本：在线安装 / 升级 / 卸载

用法：
  install.sh [动作] [选项...]

动作（缺省 install）：
  install             安装最新版（已装则等价于 update）
  update              升级到最新版
  uninstall           停止服务、清理内核规则、删除二进制与 systemd 单元
  status              显示已安装版本与线上最新版本

选项：
  -y, --yes             不交互确认（自动化必需）
  -v, --version VER     安装指定版本，如 0.0.1 或 0.0.1-pre.01
      --pre             允许预发布版参与选择（默认只看正式版）
  -b, --binary PATH     离线安装：用本地二进制，不联网下载
  -f, --force           版本相同或更低时也照做（降级需显式加此参数）
      --no-start        安装后不启动服务
      --purge           卸载时一并删除数据目录
      --check           配合 status：有更新时以退出码 10 结束

高级选项：
      --mirror PREFIX   给下载地址加加速前缀，如 https://ghfast.top/
                        也认环境变量 FRPFW_MIRROR
      --base-url URL    自建镜像的 Releases 基址
                        期望布局：<base>/download/<tag>/<file>
      --api-url URL     Releases API 基址（只有 --pre 路径用得到）
      --prefix DIR      二进制安装目录（默认 /usr/local/bin）
      --data-dir DIR    数据目录（默认 /var/lib/frpfirewall）
      --unit-dir DIR    systemd 单元目录（默认 /etc/systemd/system）
      --dry-run         只解析版本与地址，不做任何改动
  -h, --help            显示本帮助

环境变量：
  FRPFW_REPO         覆盖仓库，默认 dreamstation625/FrpFireWall
  FRPFW_MIRROR       同 --mirror
  FRPFW_GITHUB_BASE  同 --base-url
  FRPFW_API_BASE     同 --api-url
  NO_COLOR           设为非空则关闭彩色输出

退出码：
  0 成功 / 未发现更新      1 出错      2 用法错误      10 status --check 发现有更新

示例：
  # 安装最新正式版
  curl -fsSL https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh | sudo bash

  # 升级 / 卸载
  curl -fsSL .../install.sh | sudo bash -s -- update
  curl -fsSL .../install.sh | sudo bash -s -- uninstall --purge -y

  # 装某个预发布版
  curl -fsSL .../install.sh | sudo bash -s -- install -v 0.0.1-pre.01

  # 离线安装（二进制和服务单元在同一目录）
  sudo ./install.sh -b ./frpfirewall-linux-amd64
EOF
}

# ===========================================================================
# 参数解析
# ===========================================================================

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -y|--yes)        ASSUME_YES=1; shift ;;
      -f|--force)      FORCE=1; shift ;;
      --pre)           ALLOW_PRE=1; shift ;;
      --purge)         PURGE=1; shift ;;
      --no-start)      DO_START=0; shift ;;
      --check)         CHECK_ONLY=1; shift ;;
      --dry-run)       DRY_RUN=1; shift ;;
      --uninstall)     ACTION="uninstall"; shift ;;   # 兼容旧写法
      -v|--version)    PIN_VERSION="${2-}"; shift 2 ;;
      -b|--binary)     BIN_SRC="${2-}"; OFFLINE=1; shift 2 ;;
      --mirror)        MIRROR="${2-}"; shift 2 ;;
      --base-url)      RELEASES_BASE="${2-}"; shift 2 ;;
      --api-url)       API_BASE="${2-}"; shift 2 ;;
      --prefix)        PREFIX="${2-}"; shift 2 ;;
      --data-dir)      DATA_DIR="${2-}"; shift 2 ;;
      --unit-dir)      UNIT_DIR="${2-}"; shift 2 ;;
      -h|--help)       usage; exit "$EXIT_OK" ;;
      -*)              printf '未知参数: %s（用 --help 查看用法）\n' "$1" >&2; exit "$EXIT_USAGE" ;;
      # 动作名允许出现在任意位置，写成 `install.sh --pre update` 也能认
      install|update|uninstall|status) ACTION="$1"; shift ;;
      *)               printf '未知的动作或多余参数: %s（用 --help 查看用法）\n' "$1" >&2; exit "$EXIT_USAGE" ;;
    esac
  done

  # 没给动作时默认安装
  [ -n "$ACTION" ] || ACTION="install"

  # 只给了 -b，没给动作：按「有没有装过」自动决定装还是升
  if [ "$OFFLINE" -eq 1 ] && [ "$ACTION" = "install" ] && [ -x "$PREFIX/frpfirewall" ]; then
    ACTION="update"
  fi

  RELEASES_BASE="${RELEASES_BASE:-${GH_BASE}/${REPO}/releases}"

  # 单元路径在这里定，晚于 --unit-dir 的赋值
  UNIT_PATH="${UNIT_DIR%/}/${SERVICE}.service"
}

# ===========================================================================
# URL
# ===========================================================================

mirrorize() {
  if [ -n "$MIRROR" ]; then
    printf '%s/%s' "${MIRROR%/}" "$1"
  else
    printf '%s' "$1"
  fi
}

url_tag_asset()  { printf '%s/download/%s/%s' "$RELEASES_BASE" "$1" "$2"; }
url_latest_asset() { printf '%s/latest/download/%s' "$RELEASES_BASE" "$1"; }

# ===========================================================================
# 基础能力
# ===========================================================================

need_root() {
  [ "$(id -u)" -eq 0 ] || die "需要 root 权限运行（改防火墙规则与写 systemd 单元都必须）"
}

need_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd，本脚本只支持 systemd 发行版"
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

# 交互确认。从管道执行时 stdin 是脚本内容本身，直接 read 会把脚本正文
# 当成回答吃掉，所以必须显式读 /dev/tty。
confirm() {
  local prompt="$1"
  if [ "$ASSUME_YES" -eq 1 ]; then
    return 0
  fi
  if [ -r /dev/tty ]; then
    local answer=""
    printf '%s [y/N] ' "$prompt" > /dev/tty
    read -r answer < /dev/tty || return 1
    case "$answer" in
      y|Y|yes|YES|Yes) return 0 ;;
      *) return 1 ;;
    esac
  fi
  warn "当前不是交互环境，无法确认。确认要执行请加 -y。"
  return 1
}

http_download() {
  local url="$1" dest="$2"
  curl -fsSL \
    --retry 3 --retry-delay 2 \
    --connect-timeout 20 --max-time 600 \
    -A "$UA" \
    -o "$dest" "$url"
}

# 读第一跳重定向，拿到最新正式版的 tag。
#
# 用 HEAD 而不是 GitHub API，因为 API 匿名限流 60 次/小时（按出口 IP 算），
# 而 release 的下载链接走 CDN，不限流。不带 -L：跟随到底会落到签名 CDN
# 地址上，里面已经没有 tag 了，只有第一跳的 Location 才有。
probe_latest_stable_tag() {
  local url result code redirect
  url="$(mirrorize "$(url_latest_asset "$PROBE_ASSET")")"

  # curl 失败（DNS / TLS / 超时）时 %{http_code} 会是 000
  result="$(curl -sI \
    --connect-timeout 20 --max-time 60 \
    -A "$UA" -o /dev/null \
    -w '%{http_code} %{redirect_url}' "$url" 2>/dev/null)" || return 2

  code="${result%% *}"
  redirect="${result#* }"

  case "$code" in
    301|302|303|307|308) ;;
    404) return 1 ;;   # 仓库还没有正式版（只有预发布时 GitHub 就是回 404）
    *)   return 2 ;;
  esac

  # 标准布局：.../releases/download/v0.0.1/frpfirewall-linux-amd64
  local tag
  tag="$(printf '%s' "$redirect" | sed -n 's#.*/releases/download/\([^/]*\)/.*#\1#p')"
  if [ -z "$tag" ]; then
    # 镜像改写过路径时的兜底：挑出路径里第一个像版本号的部分
    tag="$(printf '%s' "$redirect" \
      | sed -n 's#.*/\(v\{0,1\}[0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\(-pre\.[0-9]\{1,\}\)\{0,1\}\)/.*#\1#p')"
  fi
  [ -n "$tag" ] || return 2

  printf '%s\n' "$tag"
}

# 列出所有 release 的 tag（含预发布），挑出解析后最大的那个。
# 只有 --pre 这条路径需要，所以只在真的用到时才请求 API。
resolve_latest_any_tag() {
  local json best="" line tag
  json="$(curl -fsSL \
      --retry 2 --connect-timeout 20 --max-time 60 \
      -A "$UA" \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      "${API_BASE%/}/repos/${REPO}/releases?per_page=100" 2>/dev/null)" || return 2

  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    vparse "$tag" >/dev/null 2>&1 || continue
    if [ -z "$best" ] || [ "$(vcmp "$tag" "$best")" = "1" ]; then
      best="$tag"
    fi
  done < <(printf '%s\n' "$json" | grep -o '"tag_name": *"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')

  [ -n "$best" ] || return 1
  printf '%s\n' "$best"
}

# 解析出本次要装的 tag（形如 v0.0.1）。失败时返回非零，由调用方给出完整报错。
resolve_target_tag() {
  if [ -n "$PIN_VERSION" ]; then
    local norm
    norm="$(vnorm "$PIN_VERSION")" || {
      printf '版本号 %s 格式非法。只接受 0.0.1 或 0.0.1-pre.01 两种形态。\n' "$PIN_VERSION" >&2
      return 1
    }
    printf 'v%s\n' "$norm"
    return 0
  fi

  if [ "$ALLOW_PRE" -eq 1 ]; then
    local tag
    tag="$(resolve_latest_any_tag)" || {
      printf '读取 release 列表失败（网络不通，或 GitHub API 匿名限流）。\n' >&2
      printf '可以改用 -v <版本号> 直接指定，或稍后重试。\n' >&2
      return 1
    }
    printf '%s\n' "$tag"
    return 0
  fi

  local tag rc=0
  tag="$(probe_latest_stable_tag)" || rc=$?
  case "$rc" in
    0) printf '%s\n' "$tag" ;;
    1)
      printf '仓库 %s 还没有正式版发布（只有预发布版本）。\n' "$REPO" >&2
      printf '想装预发布版请加 --pre 或 -v <版本号>。\n' >&2
      return 1
      ;;
    *)
      printf '访问 %s 失败：网络不通，或被墙/代理拦住了。\n' "$RELEASES_BASE" >&2
      printf '国内服务器可以加加速前缀，例如：--mirror https://ghfast.top/\n' >&2
      return 1
      ;;
  esac
}

# 已安装的版本号；没装或取不到时返回非零
installed_version() {
  local bin="$PREFIX/frpfirewall"
  [ -x "$bin" ] || return 1
  local out
  out="$("$bin" -version 2>/dev/null)" || return 1
  # 形如：FrpFireWall 0.0.1-pre.01 (commit abc1234, built ...)
  local ver
  ver="$(printf '%s' "$out" | awk 'NR==1{print $2}')"
  [ -n "$ver" ] || return 1
  vparse "$ver" >/dev/null 2>&1 || return 1
  printf '%s\n' "$ver"
}

# ===========================================================================
# 下载与校验
# ===========================================================================

# 在 sha256sums.txt 里找某个文件的期望值。
#
# 关于那几个 sub()：GNU coreutils 的 sha256sum 有两种输出形态 ——
#   hash  name    文本模式（Linux 上默认）
#   \hash *name   转义模式，文件名里含反斜杠或换行时启用
# MSYS/Git Bash 上路径天然带反斜杠，于是会走第二种，哈希前面多一个反斜杠、
# 分隔符也变成 `*`。两种都认，免得校验在非 Linux 环境下无谓地失败。
expected_sum() {
  local sums="$1" name="$2"
  awk -v n="$name" '
    {
      h = $1; sub(/^\\/, "", h)
      f = $2; sub(/^\*/, "", f)
      if (f == n) { print h; exit }
    }
  ' "$sums"
}

# verify_file <文件> <校验和文件> <名字> <是否必需>
verify_file() {
  local file="$1" sums="$2" name="$3" required="$4"
  local want got

  want="$(expected_sum "$sums" "$name")"
  if [ -z "$want" ]; then
    if [ "$required" = "1" ]; then
      die "sha256sums.txt 里没有 $name 的校验值，拒绝继续"
    fi
    warn "$name 不在 sha256sums.txt 中，跳过校验（旧版发布可能只覆盖了二进制）"
    return 0
  fi

  # 同样要吃掉 coreutils 可能加上的转义反斜杠（见 expected_sum 的注释）
  got="$(sha256sum "$file" | awk '{ h = $1; sub(/^\\/, "", h); print h }')"
  if [ "$want" != "$got" ]; then
    die "$name 校验和不匹配：期望 $want，实际 $got。下载被篡改或传输损坏，已中止。"
  fi
  dim "    sha256 ok  $name"
}

# 下载一个发布资产到工作目录：fetch_asset <tag> <文件名> <是否必需>
fetch_asset() {
  local tag="$1" name="$2" required="$3"
  local url dest
  url="$(mirrorize "$(url_tag_asset "$tag" "$name")")"
  dest="$WORKDIR/$name"

  if ! http_download "$url" "$dest"; then
    if [ "$required" = "1" ]; then
      die "下载 $name 失败：$url"
    fi
    warn "下载 $name 失败，跳过：$url"
    rm -f "$dest"
    return 1
  fi
  printf '%s\n' "$dest"
}

# ===========================================================================
# status
# ===========================================================================

do_status() {
  local cur="" target="" has_update=0 scope="仅正式版"

  cur="$(installed_version)" || cur=""
  if [ "$ALLOW_PRE" -eq 1 ]; then scope="含预发布"; fi

  printf '\n  frpfirewall 版本状态\n  %s\n' "----------------------------------------------"
  if [ -n "$cur" ]; then
    printf '  已安装    : %s\n' "$cur"
    printf '  二进制    : %s\n' "$PREFIX/frpfirewall"
  else
    printf '  已安装    : 未检测到（%s 不存在或不可执行）\n' "$PREFIX/frpfirewall"
  fi

  # 这里不吞 stderr：查询失败的原因（只有预发布 / 网络不通 / 被限流）
  # 正是用户最需要看到的东西。
  if target="$(resolve_target_tag)"; then
    printf '  最新可用  : %s（%s）\n' "${target#v}" "$scope"
    if [ -n "$cur" ]; then
      case "$(vcmp "${target#v}" "$cur" 2>/dev/null || printf 'x')" in
        1)  has_update=1
            printf '  状态      : 有新版本，执行 update 升级\n' ;;
        0)  printf '  状态      : 已是最新\n' ;;
        *)  printf '  状态      : 本地版本不低于线上最新版（本地是预发布，或已手动降级）\n' ;;
      esac
    else
      printf '  状态      : 未安装，执行 install 安装\n'
    fi
  else
    printf '  最新可用  : 查询失败（原因见上方）\n'
  fi
  printf '\n'

  if [ "$CHECK_ONLY" -eq 1 ] && [ "$has_update" -eq 1 ]; then
    return "$EXIT_HAS_UPDATE"
  fi
  return 0
}

# ===========================================================================
# install / update
# ===========================================================================

check_environment() {
  local has_ipt=0 has_nft=0
  if command_exists iptables; then has_ipt=1; fi
  if command_exists nft; then has_nft=1; fi
  if [ "$has_ipt" -eq 0 ] && [ "$has_nft" -eq 0 ]; then
    warn "既没有 iptables 也没有 nftables，网络层封禁将不可用（应用层拦截仍可工作）"
    warn "建议先安装： apt install -y nftables   或   apt install -y iptables"
  fi
  if [ "$has_nft" -eq 1 ]; then log "检测到 nftables（推荐后端）"; fi
  if [ "$has_ipt" -eq 1 ]; then log "检测到 iptables"; fi

  local tool
  for tool in ufw firewalld; do
    if command_exists "$tool"; then
      warn "检测到 $tool。frpfirewall 不会改动它已有的规则，两者可以共存"
    fi
  done
  return 0
}

# 在几个常见位置找服务单元
find_unit() {
  local cand
  for cand in \
    "$SCRIPT_DIR/frpfirewall.service" \
    "$SCRIPT_DIR/deploy/frpfirewall.service" \
    "$SCRIPT_DIR/../deploy/frpfirewall.service" \
    "/tmp/frpfirewall.service"
  do
    if [ -f "$cand" ]; then printf '%s\n' "$cand"; return 0; fi
  done
  return 1
}

find_panic() {
  local cand
  for cand in \
    "$PREFIX/frpfirewall-panic" \
    "$PREFIX/frpfirewall-panic.sh" \
    "$SCRIPT_DIR/frpfirewall-panic.sh" \
    "./frpfirewall-panic.sh"
  do
    if [ -x "$cand" ]; then printf '%s\n' "$cand"; return 0; fi
  done
  return 1
}

# 装/换服务单元。用户手工改过的话先备份到数据目录，
# 免得升级把定制内容无声抹掉。
install_unit() {
  local src="$1"
  if [ -f "$UNIT_PATH" ] && ! cmp -s "$src" "$UNIT_PATH"; then
    local backup="$DATA_DIR/frpfirewall.service.bak"
    if [ "$DRY_RUN" -eq 0 ] && [ -d "$DATA_DIR" ]; then
      cp -p "$UNIT_PATH" "$backup" 2>/dev/null || true
      warn "原有的 systemd 单元与本版本不同，已备份到 $backup"
    fi
  fi
  install -m 0644 "$src" "$UNIT_PATH"
}

# 等 service 进入 active；成功返回 0
wait_active() {
  local i
  for i in $(seq 1 12); do
    if systemctl is-active --quiet "$SERVICE"; then return 0; fi
    sleep 1
  done
  return 1
}

do_install() {
  local cur="" tag="" ver="" arch="" rc=0

  need_root
  need_systemd

  cur="$(installed_version)" || cur=""

  if [ "$ACTION" = "update" ] && [ -z "$cur" ] && [ "$OFFLINE" -eq 0 ]; then
    die "未检测到已安装的 frpfirewall，无法升级。请改用 install。"
  fi

  # ---- 定版本 ----
  if [ "$OFFLINE" -eq 1 ]; then
    [ -f "$BIN_SRC" ] || die "找不到二进制：$BIN_SRC"
    arch="$(varch)" || die "不支持的 CPU 架构：$(uname -m)（目前只发布 amd64 与 arm64）"
    local out
    out="$("$BIN_SRC" -version 2>/dev/null)" || die "无法执行 $BIN_SRC，它可能不是本机架构的二进制"
    ver="$(printf '%s' "$out" | awk 'NR==1{print $2}')"
    vparse "$ver" >/dev/null 2>&1 || die "从二进制读到的版本号无法解析：$ver"
    ver="$(vnorm "$ver")"
    tag="v$ver"
    log "离线模式：使用本机二进制，版本 $ver"
  else
    arch="$(varch)" || die "不支持的 CPU 架构：$(uname -m)（目前只发布 amd64 与 arm64）"
    if ! tag="$(resolve_target_tag)"; then
      exit "$EXIT_ERR"
    fi
    ver="${tag#v}"
    vparse "$ver" >/dev/null 2>&1 || die "解析到的版本号无法解析：$ver"
  fi

  # ---- 版本判定 ----
  if [ -n "$cur" ]; then
    case "$(vcmp "$ver" "$cur")" in
      0)
        if [ "$FORCE" -eq 0 ]; then
          log "已是最新版本 $cur，无需操作"
          if [ "$DO_START" -eq 1 ]; then
            systemctl is-active --quiet "$SERVICE" || {
              log "服务当前未运行，正在启动"
              systemctl start "$SERVICE" || die "启动失败，看日志： journalctl -u $SERVICE -n 30"
            }
          fi
          return 0
        fi
        ;;
      -1)
        if [ "$FORCE" -eq 0 ]; then
          die "目标版本 $ver 低于当前已安装的 $cur。确认要降级请加 --force。"
        fi
        warn "正在降级：$cur → $ver"
        ;;
    esac
  fi

  local verb="安装"
  if [ "$ACTION" = "update" ]; then verb="升级"; fi
  log "目标版本 $ver（${verb}，架构 $arch）"
  if [ -n "$cur" ]; then dim "    当前版本  $cur"; fi

  if [ "$DRY_RUN" -eq 1 ]; then
    dim "    [dry-run] 下载地址 $(mirrorize "$(url_tag_asset "$tag" "frpfirewall-linux-$arch")")"
    dim "    [dry-run] 校验和   $(mirrorize "$(url_tag_asset "$tag" "sha256sums.txt")")"
    dim "    [dry-run] 服务单元 $(mirrorize "$(url_tag_asset "$tag" "frpfirewall.service")")"
    dim "    [dry-run] 救援脚本 $(mirrorize "$(url_tag_asset "$tag" "frpfirewall-panic.sh")")"
    dim "    [dry-run] 不会做任何改动"
    return 0
  fi

  # ---- 环境确认（放在下载之前，早点发现问题就少等一次下载）----
  log "检查防火墙后端"
  check_environment

  # ---- 取文件 ----
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/frpfirewall-install.XXXXXX")"
  local bin_file="" unit_file="" panic_file=""

  if [ "$OFFLINE" -eq 1 ]; then
    bin_file="$BIN_SRC"
    if ! unit_file="$(find_unit)"; then
      die "未找到 frpfirewall.service，请把它和本脚本放在同一目录"
    fi
    panic_file="$(find_panic)" || panic_file=""
    warn "离线模式：跳过 sha256 校验（没有从发布拉取 sha256sums.txt）"
  else
    log "下载并校验"

    # 必需资产用 if ! … 包住：fetch_asset 里 die 的 exit 只作用于命令替换的
    # 子 shell，不这样写的话失败信息打出来了、主流程却会继续往下走。
    if ! fetch_asset "$tag" "sha256sums.txt" 1 >/dev/null; then
      exit "$EXIT_ERR"
    fi
    local sums="$WORKDIR/sha256sums.txt"

    if ! bin_file="$(fetch_asset "$tag" "frpfirewall-linux-$arch" 1)"; then
      exit "$EXIT_ERR"
    fi
    verify_file "$bin_file" "$sums" "frpfirewall-linux-$arch" 1

    if ! unit_file="$(fetch_asset "$tag" "frpfirewall.service" 1)"; then
      exit "$EXIT_ERR"
    fi
    verify_file "$unit_file" "$sums" "frpfirewall.service" 0

    # 救援脚本是可选的：早期发布里没有它，不该因此装不上
    if panic_file="$(fetch_asset "$tag" "frpfirewall-panic.sh" 0)"; then
      verify_file "$panic_file" "$sums" "frpfirewall-panic.sh" 0
    else
      panic_file=""
      warn "本次发布没有附带救援脚本，卸载时将无法自动清理内核规则"
    fi
  fi

  # ---- 先落那些「会失败但不该留下半残状态」的东西 ----
  # 顺序是有意的：写 systemd 单元、建数据目录都可能失败（权限、目录不存在、
  # 磁盘满）。这些必须在动二进制之前做完，否则会出现「二进制已经换成新版、
  # 服务却还跑着旧版」这种两边不一致的状态，比直接失败更难排查。
  install -d -m 0755 "$UNIT_DIR"
  install -d -m 0750 -o root -g root "$DATA_DIR"

  local first_install=0
  [ -f "$DATA_DIR/frpfirewall.db" ] || first_install=1

  # ---- systemd 单元 ----
  log "安装 systemd 单元"
  install_unit "$unit_file"
  systemctl daemon-reload

  # ---- 换二进制 ----
  # 先落到临时名再 mv：mv 换的是 inode，不会让正在运行的进程读到半个文件
  # （原地覆盖可执行文件会拿到 ETXTBSY）。
  install -d -m 0755 "$PREFIX"
  local prev="$PREFIX/frpfirewall.prev"
  rm -f "$prev"

  log "安装二进制到 $PREFIX/frpfirewall"
  install -m 0755 -o root -g root "$bin_file" "$PREFIX/frpfirewall.new"

  # 备份用硬链接而不是复制：瞬间完成，且在新文件顶上来之前不额外占空间
  if [ -x "$PREFIX/frpfirewall" ]; then
    if ! ln -f "$PREFIX/frpfirewall" "$prev" 2>/dev/null; then
      cp -p "$PREFIX/frpfirewall" "$prev" 2>/dev/null \
        || warn "旧二进制备份失败，本次升级将无法自动回滚"
    fi
  fi
  mv -f "$PREFIX/frpfirewall.new" "$PREFIX/frpfirewall"

  if [ -n "$panic_file" ]; then
    install -m 0755 -o root -g root "$panic_file" "$PREFIX/frpfirewall-panic"
    log "救援脚本已装到 $PREFIX/frpfirewall-panic"
  fi

  systemctl enable "$SERVICE" >/dev/null 2>&1 \
    || warn "开机自启设置失败，可手动执行： systemctl enable $SERVICE"

  if [ "$DO_START" -eq 0 ]; then
    log "已按 --no-start 跳过启动"
    if [ -x "$prev" ]; then
      dim "    旧二进制留在 $prev，确认新版没问题后可删掉"
    fi
  else
    log "启动服务"
    systemctl restart "$SERVICE" || true

    if wait_active; then
      log "服务已运行"
      # 起来了才敢把回滚用的备份删掉
      rm -f "$prev"
      local running=""
      running="$(installed_version)" || running=""
      if [ -n "$running" ] && [ "$running" != "$ver" ]; then
        warn "服务报告的版本是 $running，与目标 $ver 不符，请检查"
      fi
    else
      warn "新版本启动失败，最近日志："
      journalctl -u "$SERVICE" -n 30 --no-pager 2>/dev/null || true
      if [ -x "$prev" ]; then
        warn "正在回滚到升级前的二进制"
        mv -f "$prev" "$PREFIX/frpfirewall"
        systemctl restart "$SERVICE" || true
        if wait_active; then
          die "已回滚，服务恢复正常。新版本 $ver 有问题，请带上上面的日志反馈。"
        fi
        die "回滚后仍无法启动，请手动排查： journalctl -xeu $SERVICE"
      fi
      die "启动失败"
    fi
  fi

  # ---- 结果 ----
  echo
  echo "=============================================================="
  if [ "$ACTION" = "update" ] && [ -n "$cur" ]; then
    printf ' frpfirewall 已升级：%s → %s\n' "$cur" "$ver"
  else
    printf ' frpfirewall %s 安装完成\n' "$ver"
  fi
  echo "=============================================================="

  if [ "$first_install" = "1" ]; then
    echo
    echo " 面板地址：   http://<本机IP>:7930"
    if [ -f "$DATA_DIR/setup_token.txt" ]; then
      echo " 初始化令牌： $(head -1 "$DATA_DIR/setup_token.txt")"
      echo
      echo " 打开面板后填入令牌并自行设置管理员密码，"
      echo " 令牌设置完成后自动作废，文件也会被删除。"
    else
      echo
      echo " 初始化令牌稍后可从日志中查看："
      echo "   journalctl -u frpfirewall | grep 初始化令牌"
      echo "   或 cat $DATA_DIR/setup_token.txt"
    fi
    echo
    echo " 接下来还要做一件事：把插件配置加进 frps.toml"
    echo "   面板 → frp 接入 → 复制配置片段 → 追加到 /etc/frp/frps.toml"
    echo "   然后 systemctl restart frps"
  fi

  echo
  echo " 常用命令："
  echo "   查看状态   systemctl status frpfirewall"
  echo "   查看日志   journalctl -u frpfirewall -f"
  echo "   检查更新   <本脚本> status"
  echo "   升级       <本脚本> update"
  echo "   紧急清规则 sudo frpfirewall-panic"
  echo "   卸载       <本脚本> uninstall"
  echo "=============================================================="
}

# ===========================================================================
# uninstall
# ===========================================================================

# 数据目录删除前的护栏。宁可多拦几次，也不能让 --purge 误伤别的目录。
# 注意调用时机：必须在动任何东西之前就跑一遍，否则会出现
# 「应用已经删掉了，才告诉你数据目录不许删」这种半途而废的状态。
guard_data_dir() {
  # 明确的系统目录一律拒绝（这一条要放在路径深度检查之前，
  # 否则 /etc 会先被「必须是两层以上」的理由挡掉，提示反而不准确）
  case "$DATA_DIR" in
    /bin|/boot|/dev|/etc|/home|/lib|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      die "拒绝删除：$DATA_DIR 是系统目录" ;;
  esac

  # 空值、根、相对路径都不接受
  case "$DATA_DIR" in
    ""|"/"|"."|"..") die "拒绝删除：数据目录是「$DATA_DIR」" ;;
    /*/*) ;;
    *) die "拒绝删除：数据目录必须是至少两层的绝对路径，当前为「$DATA_DIR」" ;;
  esac

  # 只认自己建的目录：要么是空的，要么里面有本程序的数据库。
  # 这一条挡的是「--data-dir 手滑指到了别的应用目录」。
  if [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ] \
     && [ ! -f "$DATA_DIR/frpfirewall.db" ]; then
    die "拒绝删除：$DATA_DIR 非空且不含 frpfirewall.db，看起来不是本程序的数据目录"
  fi
  return 0
}

do_uninstall() {
  need_root
  need_systemd

  # 先验后动：--purge 的目标不合法就立刻退出，别把应用删了一半才报错
  if [ "$PURGE" -eq 1 ]; then
    guard_data_dir
  fi

  local ver=""
  ver="$(installed_version)" || ver=""

  log "停止并禁用服务"
  systemctl stop "$SERVICE" 2>/dev/null || true
  systemctl disable "$SERVICE" 2>/dev/null || true

  # ---- 清内核规则 ----
  # 必须在停服之后：进程还在跑的话，下一次 reconcile 会把规则重新下发。
  log "清理内核里残留的受管规则"
  local panic=""
  if panic="$(find_panic)"; then
    "$panic" --yes || warn "救援脚本返回非零，可能有规则没清干净"
  elif [ "$OFFLINE" -eq 0 ]; then
    # 本机没留救援脚本（旧版本装的），从发布里临时拉一个
    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/frpfirewall-uninstall.XXXXXX")"
    local tag=""
    if [ -n "$ver" ]; then tag="v$ver"; fi
    if [ -n "$tag" ] \
      && http_download "$(mirrorize "$(url_tag_asset "$tag" "frpfirewall-panic.sh")")" "$WORKDIR/panic.sh" 2>/dev/null; then
      chmod +x "$WORKDIR/panic.sh"
      "$WORKDIR/panic.sh" --yes || warn "救援脚本返回非零"
    else
      warn "拿不到救援脚本，内核规则可能仍有残留。"
      warn "联网后手动执行清理： curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/frpfirewall-panic.sh | sudo bash"
    fi
  else
    warn "离线模式下未找到救援脚本，内核规则可能仍有残留"
    warn "请手动执行 frpfirewall-panic.sh 清理"
  fi

  # ---- 删单元与二进制 ----
  log "删除 systemd 单元与二进制"
  rm -f "$UNIT_PATH"
  systemctl daemon-reload 2>/dev/null || true
  rm -f "$PREFIX/frpfirewall" "$PREFIX/frpfirewall.prev"
  rm -f "$PREFIX/frpfirewall-panic" "$PREFIX/frpfirewall-panic.sh"

  # ---- 数据目录 ----
  local purged=0
  if [ "$PURGE" -eq 1 ]; then
    if [ -d "$DATA_DIR" ]; then
      local size
      size="$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)"
      if confirm "即将永久删除 $DATA_DIR（${size:-未知大小}），含封禁记录、白名单与面板密码，且无法恢复。确定？"; then
        rm -rf "$DATA_DIR"
        purged=1
      else
        warn "已按你的选择保留数据目录"
      fi
    fi
  fi

  echo
  echo "=============================================================="
  echo " frpfirewall 已卸载"
  echo "=============================================================="
  if [ "$purged" -eq 1 ]; then
    echo " 数据目录已删除：$DATA_DIR"
  else
    echo " 以下内容被保留（确认不需要再手动删）："
    echo "   数据目录：$DATA_DIR"
    echo "   删除它：  sudo rm -rf $DATA_DIR   或者重新执行 uninstall --purge"
  fi
  echo
  echo " frps 侧别忘了：把 frps.toml 里的 [[httpPlugins]] 段删掉后重启 frps"
  echo "   否则 frps 会因为回调插件不通而拒绝所有用户登录"
  echo "=============================================================="
}

# ===========================================================================
# 入口
# ===========================================================================

parse_args "$@"

case "$ACTION" in
  install|update) do_install ;;
  uninstall)      do_uninstall ;;
  status)         do_status ;;
  *)              usage; exit "$EXIT_USAGE" ;;
esac
