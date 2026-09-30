#!/usr/bin/env bash
#
# frpfirewall 一键安装 / 升级脚本（Debian / Ubuntu 系）
#
# 做的事情：
#   1. 校验运行环境（root、systemd、iptables 或 nftables 至少有一个）
#   2. 安装二进制到 /usr/local/bin/frpfirewall
#   3. 创建数据目录 /var/lib/frpfirewall（配置存在该目录的 SQLite 数据库里）
#   4. 注册 systemd 服务并设置开机自启
#   5. 打印初始化令牌与后续操作提示
#
# 用法：
#   ./install.sh                    用同目录下的 frpfirewall 二进制安装
#   ./install.sh -b /path/to/frpfirewall  指定二进制路径
#   ./install.sh --no-start         只装不启动
#   ./install.sh --uninstall        卸载
#
set -euo pipefail

BIN_SRC=""
DO_START=1
PREFIX="/usr/local/bin"
DATA_DIR="/var/lib/frpfirewall"
UNIT_SRC=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    -b|--binary)   BIN_SRC="$2"; shift 2 ;;
    --no-start)    DO_START=0; shift ;;
    --uninstall)   UNINSTALL=1; shift ;;
    -h|--help)     awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "需要 root 权限运行"
command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd，本脚本只支持 systemd 发行版"

# ---------- 卸载 ----------
if [ "${UNINSTALL:-0}" = "1" ]; then
  log "停止并卸载服务"
  systemctl stop frpfirewall 2>/dev/null || true
  systemctl disable frpfirewall 2>/dev/null || true
  log "清理内核里残留的受管规则"
  if [ -x "$SCRIPT_DIR/frpfirewall-panic.sh" ]; then
    "$SCRIPT_DIR/frpfirewall-panic.sh" --yes || true
  elif [ -x "./frpfirewall-panic.sh" ]; then
    ./frpfirewall-panic.sh --yes || true
  fi
  rm -f /etc/systemd/system/frpfirewall.service
  systemctl daemon-reload
  rm -f "$PREFIX/frpfirewall"
  echo
  log "已卸载。以下内容被保留（确认不需要再手动删）："
  echo "   数据目录：$DATA_DIR"
  exit 0
fi

# ---------- 定位二进制 ----------
if [ -z "$BIN_SRC" ]; then
  for cand in "$SCRIPT_DIR/frpfirewall" "./frpfirewall" "$SCRIPT_DIR/../dist/frpfirewall"; do
    [ -f "$cand" ] && { BIN_SRC="$cand"; break; }
  done
fi
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || die "未找到 frpfirewall 二进制，用 -b 指定路径（先执行 make release 构建）"

# ---------- 环境检查 ----------
log "检查防火墙后端"
HAS_IPT=0; HAS_NFT=0
command -v iptables >/dev/null 2>&1 && HAS_IPT=1
command -v nft >/dev/null 2>&1 && HAS_NFT=1
if [ "$HAS_IPT" -eq 0 ] && [ "$HAS_NFT" -eq 0 ]; then
  warn "既没有 iptables 也没有 nftables，网络层封禁将不可用（应用层拦截仍可工作）"
  warn "建议先安装： apt install -y nftables   或   apt install -y iptables"
fi
[ "$HAS_NFT" -eq 1 ] && log "检测到 nftables（推荐后端）"
[ "$HAS_IPT" -eq 1 ] && log "检测到 iptables"

# 同机的其它防火墙管理工具提醒
for tool in ufw firewalld; do
  if command -v "$tool" >/dev/null 2>&1; then
    warn "检测到 $tool。frpfirewall 不会改动它已有的规则，两者可以共存"
  fi
done

# ---------- 安装二进制 ----------
log "安装二进制到 $PREFIX/frpfirewall"
install -m 0755 -o root -g root "$BIN_SRC" "$PREFIX/frpfirewall.new"
mv -f "$PREFIX/frpfirewall.new" "$PREFIX/frpfirewall"

# ---------- 数据目录 ----------
# 配置、名单、封禁记录都在这个目录的 SQLite 里，没有独立的配置文件。
FIRST_INSTALL=0
[ -f "$DATA_DIR/frpfirewall.db" ] || FIRST_INSTALL=1
install -d -m 0750 -o root -g root "$DATA_DIR"

# ---------- systemd ----------
UNIT=""
for cand in "$SCRIPT_DIR/frpfirewall.service" "$SCRIPT_DIR/deploy/frpfirewall.service" \
            "$SCRIPT_DIR/../deploy/frpfirewall.service" "/tmp/frpfirewall.service"; do
  [ -f "$cand" ] && { UNIT="$cand"; break; }
done

if [ -n "$UNIT" ]; then
  log "安装 systemd 单元（来自 $UNIT）"
  install -m 0644 "$UNIT" /etc/systemd/system/frpfirewall.service
else
  die "未找到 frpfirewall.service，请把它和本脚本放在同一目录"
fi

systemctl daemon-reload
systemctl enable frpfirewall >/dev/null

if [ "$DO_START" -eq 1 ]; then
  log "启动服务"
  systemctl restart frpfirewall
  sleep 2
  if systemctl is-active --quiet frpfirewall; then
    log "服务已运行"
  else
    warn "服务未能启动，最近日志："
    journalctl -u frpfirewall -n 30 --no-pager || true
    die "启动失败"
  fi
fi

# ---------- 结果 ----------
echo
echo "=============================================================="
echo " frpfirewall 安装完成"
echo "=============================================================="

if [ "$FIRST_INSTALL" = "1" ]; then
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
fi

echo
echo " 接下来还要做一件事：把插件配置加进 frps.toml"
echo "   面板 → frp 接入 → 复制配置片段 → 追加到 /etc/frp/frps.toml"
echo "   然后 systemctl restart frps"
echo
echo " 常用命令："
echo "   查看状态   systemctl status frpfirewall"
echo "   查看日志   journalctl -u frpfirewall -f"
echo "   紧急清规则 $SCRIPT_DIR/frpfirewall-panic.sh"
echo "=============================================================="
