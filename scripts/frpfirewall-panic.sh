#!/usr/bin/env bash
#
# frpfirewall-panic.sh —— 紧急救援：把所有由 frpfirewall 下发的防火墙规则从内核里摘掉。
#
# 什么时候用：
#   · 误封导致自己 / 重要节点连不上 frps，通过面板解封已经来不及
#   · 规则下发后出现异常流量中断，需要第一时间恢复网络
#   · frpfirewall 进程异常退出后，想彻底清干净再重装
#
# 安全边界（重要）：
#   本脚本只删除**归属 frpfirewall 的对象**，绝不 flush 整表、不动系统原有规则：
#     iptables : 只删 INPUT/FORWARD 里指向 FRPFIREWALL_GUARD 的跳转，
#                以及 FRPFIREWALL_GUARD / FRPFIREWALL_BLACK / FRPFIREWALL_BLACK_FRP 三条链
#     nftables : 只删 comment 以 "frpfirewall:" 开头的规则，以及 frpfirewall_* 集合
#   白名单不落内核，无需清理。系统已有的 ufw / firewalld / 手工规则不受影响。
#
# 用法：
#   ./frpfirewall-panic.sh              立即执行
#   ./frpfirewall-panic.sh --dry-run    只打印将要执行的命令，不做任何改动
#   ./frpfirewall-panic.sh --yes        跳过交互确认（适合写进自动化 / 远程脚本）
#
set -u

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) DRY_RUN=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    -h|--help)    awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "未知参数: $arg（用 --help 查看用法）" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：需要 root 权限（改防火墙规则必须）" >&2
  exit 1
fi

CHANGED=0
FAILED=0

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$*"
  else
    if "$@" 2>/dev/null; then
      printf '  ok   %s\n' "$*"
    else
      printf '  --   %s（对象不存在或已被清理）\n' "$*"
    fi
  fi
}

# 真正会改动的命令，失败时单独计数
run_strict() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s\n' "$*"
    return 0
  fi
  if "$@" 2>/dev/null; then
    printf '  ok   %s\n' "$*"
    CHANGED=$((CHANGED + 1))
  else
    printf '  !!   %s 失败\n' "$*" >&2
    FAILED=$((FAILED + 1))
  fi
}

echo "=============================================================="
echo " frpfirewall 紧急救援：清理受管防火墙规则"
[ "$DRY_RUN" -eq 1 ] && echo " 模式：DRY-RUN（不会做任何改动）"
echo "=============================================================="

# ---------- 1. iptables / ip6tables ----------
ipt_cleaned=0
for bin in iptables ip6tables; do
  command -v "$bin" >/dev/null 2>&1 || continue
  echo
  echo "[$bin]"

  # 先把指向受管链的跳转摘掉。顺序不能反：链上还有引用时 -X 会报错。
  for hook in INPUT FORWARD; do
    for _ in $(seq 1 10); do
      "$bin" -w -C "$hook" -j FRPFIREWALL_GUARD >/dev/null 2>&1 || break
      run_strict "$bin" -w -D "$hook" -j FRPFIREWALL_GUARD
      ipt_cleaned=1
      [ "$FAILED" -gt 0 ] && break
      [ "$DRY_RUN" -eq 1 ] && break
    done
  done

  # 先清空主链解除子链引用，再删除各条受管链。
  for chain in FRPFIREWALL_GUARD FRPFIREWALL_BLACK FRPFIREWALL_BLACK_FRP; do
    if "$bin" -w -S "$chain" >/dev/null 2>&1; then
      run_strict "$bin" -w -F "$chain"
      ipt_cleaned=1
    fi
  done
  for chain in FRPFIREWALL_GUARD FRPFIREWALL_BLACK FRPFIREWALL_BLACK_FRP; do
    if "$bin" -w -S "$chain" >/dev/null 2>&1; then run_strict "$bin" -w -X "$chain"; fi
  done

done

# ---------- 2. nftables ----------
nft_cleaned=0
if command -v nft >/dev/null 2>&1; then
  echo
  echo "[nft]"

  # nft -a list ruleset 的文本结构：
  #   table <family> <table> {
  #     chain <chain> {
  #       ... comment "frpfirewall:xxx" # handle <N>
  # 用 awk 跟踪当前 table/chain，把带 frpfirewall 注释的规则 handle 挑出来。
  rules_file=$(mktemp /tmp/frpfirewall-panic-rules.XXXXXX) || exit 1
  sets_file=$(mktemp /tmp/frpfirewall-panic-sets.XXXXXX) || { rm -f "$rules_file"; exit 1; }
  trap 'rm -f "$rules_file" "$sets_file"' EXIT
  nft -a list ruleset >"$rules_file" 2>/dev/null || { echo "读取 nft 规则失败" >&2; exit 1; }

  awk '
    /^[[:space:]]*table[[:space:]]/ {
      fam = $2; tbl = $3; sub(/[[:space:]]*\{.*/, "", tbl)
    }
    /^[[:space:]]*chain[[:space:]]/ {
      ch = $2; sub(/[[:space:]]*\{.*/, "", ch)
    }
    /set[[:space:]]+frpfirewall_/ {
      s = $2; sub(/[[:space:]]*\{.*/, "", s)
      if (fam != "" && tbl != "" && s ~ /^frpfirewall_/) print fam, tbl, s
      next
    }
    /comment[[:space:]]+"frpfirewall:/ {
      if (match($0, /# handle [0-9]+/)) {
        h = substr($0, RSTART + 9, RLENGTH - 9)
        print fam, tbl, ch, h
      }
    }
  ' "$rules_file" >"$sets_file"

  # 规则必须先删：集合被规则引用时无法删除
  rule_count=0
  while read -r fam tbl ch h; do
    [ -n "${fam:-}" ] || continue
    run_strict nft delete rule "$fam" "$tbl" "$ch" handle "$h"
    rule_count=$((rule_count + 1))
    nft_cleaned=1
  done < <(awk 'NF==4' "$sets_file")

  # DROP / RETURN 规则已按归属删除，空的限速子链可以安全移除。
  while read -r fam tbl ch; do
    [ -n "${fam:-}" ] || continue
    run_strict nft delete chain "$fam" "$tbl" "$ch"
  done < <(awk '/^[[:space:]]*table[[:space:]]/ {f=$2;t=$3} /^[[:space:]]*chain[[:space:]]+frpfirewall_rate_guard[[:space:]]/ {print f,t,$2}' "$rules_file")

  set_count=0
  while read -r fam tbl s; do
    [ -n "${fam:-}" ] || continue
    run_strict nft delete set "$fam" "$tbl" "$s"
    set_count=$((set_count + 1))
    nft_cleaned=1
  done < <(awk 'NF==3' "$sets_file")

  if [ "$rule_count" -eq 0 ] && [ "$set_count" -eq 0 ]; then
    echo "  --   未发现 frpfirewall 归属的规则或集合"
  else
    echo " 总计：规则 $rule_count 条，集合 $set_count 个"
  fi

  rm -f "$rules_file" "$sets_file"
else
  echo
  echo "[nft] 未安装 nft，跳过"
fi

# ---------- 3. 结果 ----------
echo
echo "=============================================================="
if [ "$DRY_RUN" -eq 1 ]; then
  echo " DRY-RUN 结束，未做任何改动。去掉 --dry-run 即真正执行。"
else
  if [ "$ipt_cleaned" -eq 0 ] && [ "$nft_cleaned" -eq 0 ]; then
    echo " 内核里没有发现 frpfirewall 的规则，无需清理。"
  else
    echo " 清理完成。"
  fi
  if [ "$FAILED" -gt 0 ]; then
    echo " 有 $FAILED 条命令失败，请检查上面的输出。"
    echo " 注意：如果 frpfirewall 进程仍在运行，它会在下一次 reconcile 时把规则重新下发。"
    echo "       要彻底停用，请先执行： systemctl stop frpfirewall"
  fi
  echo
  echo " 提示：本脚本只清理网络层。应用层的封禁记录还在数据库里，"
  echo "       重启 frpfirewall 后会按数据库状态重新下发，如需彻底重置请清空 <data_dir>/frpfirewall.db。"
fi
echo "=============================================================="
[ "$FAILED" -eq 0 ]
