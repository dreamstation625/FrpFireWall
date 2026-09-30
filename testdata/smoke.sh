#!/usr/bin/env bash
# FrpFireWall 冒烟测试：验证嵌入的前端产物 + 全部管理接口 + frps 插件回调。
#
# 用法：
#   1) 先启动服务： ./testdata/frpfirewall.exe -data testdata/data
#   2) 再执行：     bash testdata/smoke.sh
#
# 说明：
#   · 数据目录为空时会走一遍初始化流程（读 setup_token.txt 设置密码）
#   · 数据目录已初始化时用固定测试密码登录，脚本可重复运行
#   · 脚本会临时改写策略与配置，结束时恢复
set -u

BASE="http://127.0.0.1:7930"
PLUGIN="http://127.0.0.1:9100"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="testdata/data"
SMOKE_PW="smoke-test-pass"
cd "$ROOT" || exit 1

# 期望版本号直接取自 VERSION 文件（构建时经 -ldflags 注入二进制）。
# 不要在这里写死字面量，否则每次升版本都要回来改一遍。
# 注：如果二进制是旧的没重新编译，这里会失败——那是有效信号，不是脚本误报。
EXPECT_VERSION="$(tr -d ' \t\r\n' < VERSION 2>/dev/null)"

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
export PATH="/c/Users/dream/.workbuddy/binaries/PortableGit/versions/1.2.0/usr/bin:/c/Users/dream/.workbuddy/binaries/node/versions/22.22.2-3:$PATH"

CURL=(curl -s -S --noproxy '*' -m 15)
PASS=0
FAIL=0

get() { "${CURL[@]}" "$@"; }
# 取 JSON 里某个点分路径的值（数组打印成 [长度]）
jqf() { node "$ROOT/testdata/jq.js" "$1"; }
# 取出 data 子对象，用于回填后再 PUT
jqd() { node "$ROOT/testdata/jq.js" data; }
mut() { node "$ROOT/testdata/mutate.js" "$@"; }

# frps 插件回调的构造与发送（多处用到，统一放这里）
login_body() {
  printf '{"version":"0.1.0","op":"Login","content":{"version":"0.52.0","hostname":"smoke","os":"linux","arch":"amd64","user":"","privilege_key":"x","timestamp":0,"run_id":"%s","pool_count":1,"metas":{},"client_address":"%s"}}' "$1" "$2"
}
post_op() { get -X POST "$PLUGIN/frps/handler?version=0.1.0&op=$1" -H 'Content-Type: application/json' -d "$2"; }

green() { printf '\033[32m%s\033[0m' "$1"; }
red() { printf '\033[31m%s\033[0m' "$1"; }

# 精确断言
check() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    printf '  %s %-44s %s\n' "$(green PASS)" "$label" "$got"; PASS=$((PASS + 1))
  else
    printf '  %s %-44s got=%s want=%s\n' "$(red FAIL)" "$label" "$got" "$want"; FAIL=$((FAIL + 1))
  fi
}

# 只要求非空且不含解析错误（允许空字符串的场景改用 check_any）
check_ok() {
  local label="$1" got="$2"
  if [ -n "$got" ] && [ "$got" != "undefined" ] && [ "$got" != "null" ] && [ "${got:0:9}" != "PARSE_ERR" ]; then
    printf '  %s %-44s %s\n' "$(green PASS)" "$label" "$got"; PASS=$((PASS + 1))
  else
    printf '  %s %-44s %s\n' "$(red FAIL)" "$label" "$got"; FAIL=$((FAIL + 1))
  fi
}

# 只要求不是解析错误（null / 空串也算通过）
check_any() {
  local label="$1" got="$2"
  if [ "${got:0:9}" != "PARSE_ERR" ] && [ "$got" != "undefined" ]; then
    printf '  %s %-44s %s\n' "$(green PASS)" "$label" "$got"; PASS=$((PASS + 1))
  else
    printf '  %s %-44s %s\n' "$(red FAIL)" "$label" "$got"; FAIL=$((FAIL + 1))
  fi
}

# 断言是 JSON 数组：数组会被 jqf 打印成 [长度]，null 不是数组。
# 列表类字段必须返回 []，不能返回 null，否则前端处处要兜底。
check_list() {
  local label="$1" got="$2"
  if [[ "$got" =~ ^\[[0-9]+\]$ ]]; then
    printf '  %s %-44s %s\n' "$(green PASS)" "$label" "$got"; PASS=$((PASS + 1))
  else
    printf '  %s %-44s %s\n' "$(red FAIL)" "$label" "$got"; FAIL=$((FAIL + 1))
  fi
}

# 断言是非空 JSON 数组
check_list_nonempty() {
  local label="$1" got="$2"
  if [[ "$got" =~ ^\[[0-9]+\]$ ]] && [ "${got:1:${#got}-2}" -gt 0 ] 2>/dev/null; then
    printf '  %s %-44s %s\n' "$(green PASS)" "$label" "$got"; PASS=$((PASS + 1))
  else
    printf '  %s %-44s %s\n' "$(red FAIL)" "$label" "$got"; FAIL=$((FAIL + 1))
  fi
}

# 断言错误信息包含某个关键词
check_err() {
  local label="$1" got="$2" want="$3"
  case "$got" in
    *"$want"*) printf '  %s %-44s %s\n' "$(green PASS)" "$label" "$got"; PASS=$((PASS + 1)) ;;
    *) printf '  %s %-44s got=%s 应包含=%s\n' "$(red FAIL)" "$label" "$got" "$want"; FAIL=$((FAIL + 1)) ;;
  esac
}

# ---------- 前置连通性预检 ----------
# 没有这一步时，服务没起来 / 二进制是旧的 表现为满屏 PARSE_ERR，
# 最后在 $((BEFORE + 1)) 这类算术展开处直接崩掉（set -u 下 "PARSE_ERR" 被当成变量名），
# 看不到任何失败汇总，很难判断根因。这里先拦一道，直接给明白话。
preflight() {
  local url="$1" name="$2"
  if ! "${CURL[@]}" -o /dev/null "$url" 2>/dev/null; then
    printf '\n%s\n' "$(red "无法连接 ${name}：${url}")"
    echo "请先启动被测实例（二进制需与本轮代码一致）："
    echo "    ./testdata/frpfirewall.exe -data testdata/data"
    echo "若刚跑过一次失败，先确认旧进程没占着端口："
    echo "    netstat -ano | grep LISTENING | grep -E ':7930|:9100'"
    exit 2
  fi
}
preflight "$BASE/" "面板"
preflight "$PLUGIN/frps/handler" "frps 插件服务"

echo "########## 1. 前端产物（go:embed + SPA 回退） ##########"
code=$(get -o /tmp/spa.html -w '%{http_code}' "$BASE/")
check "GET / 返回首页" "$code" "200"
echo "  index.html $(wc -c < /tmp/spa.html) bytes"
JS=$(grep -o 'assets/index-[A-Za-z0-9_-]*\.js' /tmp/spa.html | head -1)
CSS=$(grep -o 'assets/index-[A-Za-z0-9_-]*\.css' /tmp/spa.html | head -1)
check "入口 JS 可访问 ($JS)" "$(get -o /dev/null -w '%{http_code}' "$BASE/$JS")" "200"
check "入口 CSS 可访问 ($CSS)" "$(get -o /dev/null -w '%{http_code}' "$BASE/$CSS")" "200"
check "JS Content-Type" "$(get -o /dev/null -w '%{content_type}' "$BASE/$JS")" "application/javascript"
check "CSS Content-Type" "$(get -o /dev/null -w '%{content_type}' "$BASE/$CSS")" "text/css; charset=utf-8"
check "未知路径回退到 SPA" "$(get -o /dev/null -w '%{http_code}' "$BASE/unknown/path")" "200"
# 非 API 路径一律回退到 index.html，绝不能把仓库里的源码文件当静态资源吐出去
if get "$BASE/go.mod" | grep -q 'module '; then
  printf '  %s %-44s 源码文件被当成静态资源泄露\n' "$(red FAIL)" "非 API 路径不回吐源码"; FAIL=$((FAIL + 1))
else
  printf '  %s %-44s 已回退到 index.html\n' "$(green PASS)" "非 API 路径不回吐源码"; PASS=$((PASS + 1))
fi
for v in Policy GeoIP Frps Events ACL Bans Dashboard Firewall Login MainLayout Setup Settings; do
  f=$(ls internal/web/dist/assets/ 2>/dev/null | grep -E "^${v}-.*\.js$" | head -1)
  if [ -n "$f" ]; then
    printf '  %s %-44s %s\n' "$(green PASS)" "页面 chunk 已打包: $v" "$f"; PASS=$((PASS + 1))
  else
    printf '  %s %-44s 未找到\n' "$(red FAIL)" "页面 chunk 已打包: $v"; FAIL=$((FAIL + 1))
  fi
done

echo
echo "########## 2. 初始化与认证 ##########"
if [ "$(get "$BASE/api/v1/auth/status" | jqf data.initialized)" = "true" ]; then
  # 已经初始化过：直接用固定测试密码登录
  LOGIN=$(get -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$SMOKE_PW\"}")
  TOKEN=$(printf '%s' "$LOGIN" | jqf data.token)
  check_ok "登录拿到 JWT (长度 ${#TOKEN})" "$TOKEN"
else
  check "未初始化时 initialized=false" "$(get "$BASE/api/v1/auth/status" | jqf data.initialized)" "false"

  # 令牌不对必须拒绝，否则面板开在公网等于谁都能把自己设成管理员
  check "错误初始化令牌被拒" \
    "$(get -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/setup" -H 'Content-Type: application/json' \
       -d '{"token":"wrong-token-value","username":"admin","password":"smoke-test-pass"}')" "401"

  SETUP_TOKEN=$(head -1 "$DATA_DIR/setup_token.txt" 2>/dev/null | tr -d '\r\n')
  check_ok "读到初始化令牌" "$SETUP_TOKEN"
  check "过短密码被拒" \
    "$(get -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/setup" -H 'Content-Type: application/json' \
       -d "{\"token\":\"$SETUP_TOKEN\",\"username\":\"admin\",\"password\":\"short\"}")" "400"

  LOGIN=$(get -X POST "$BASE/api/v1/auth/setup" -H 'Content-Type: application/json' \
    -d "{\"token\":\"$SETUP_TOKEN\",\"username\":\"admin\",\"password\":\"$SMOKE_PW\"}")
  TOKEN=$(printf '%s' "$LOGIN" | jqf data.token)
  check_ok "初始化后直接拿到 JWT (长度 ${#TOKEN})" "$TOKEN"

  check "已初始化后 initialized=true" "$(get "$BASE/api/v1/auth/status" | jqf data.initialized)" "true"
  check "重复初始化被拒" \
    "$(get -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/setup" -H 'Content-Type: application/json' \
       -d "{\"token\":\"$SETUP_TOKEN\",\"username\":\"admin\",\"password\":\"$SMOKE_PW\"}")" "409"
  check "初始化令牌文件已删除" \
    "$([ -f "$DATA_DIR/setup_token.txt" ] && echo exists || echo gone)" "gone"
fi

AUTH="Authorization: Bearer $TOKEN"
check "无 token 访问 /policy" "$(get -o /dev/null -w '%{http_code}' "$BASE/api/v1/policy")" "401"
check "伪造 token 访问 /policy" "$(get -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer aaa.bbb.ccc' "$BASE/api/v1/policy")" "401"
check "错误密码登录" "$(get -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"nope"}')" "401"
check "带 token 访问 /auth/me" "$(get -o /dev/null -w '%{http_code}' -H "$AUTH" "$BASE/api/v1/auth/me")" "200"
check "用户名为 admin" "$(get -H "$AUTH" "$BASE/api/v1/auth/me" | jqf data.username)" "admin"

echo
echo "########## 3. 策略接口（Policy.vue 字段对齐） ##########"
POL=$(get -H "$AUTH" "$BASE/api/v1/policy")
BODY=$(printf '%s' "$POL" | jqd)
check_ok "策略对象可解析" "$(printf '%s' "$BODY" | jqf window_seconds)"
for k in window_seconds threshold ban_durations escalate_window_hours ban_granularity \
         fail_mode auto_ban_enabled observe_only geoip_block_enabled geoip_mode \
         rate_limit_enabled rate_limit_per_sec rate_limit_burst; do
  check_ok "字段 $k" "$(printf '%s' "$POL" | jqf "data.$k")"
done
check_any "字段 geoip_block_countries（默认空）" "$(printf '%s' "$POL" | jqf data.geoip_block_countries)"

echo
echo "########## 4. 策略写入与校验 ##########"
R=$(printf '%s' "$BODY" | mut ban_durations=600,3600,86400,0 -id -updated_at > /tmp/m1.json; \
    get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/m1.json)
check "写入阶梯时长" "$(printf '%s' "$R" | jqf data.ban_durations)" "600,3600,86400,0"

R=$(printf '%s' "$BODY" | mut rate_limit_enabled=true rate_limit_per_sec=25 rate_limit_burst=50 -id -updated_at > /tmp/m2.json; \
    get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/m2.json)
check "写入速率限制 25/50" "$(printf '%s' "$R" | jqf data.rate_limit_per_sec)/$(printf '%s' "$R" | jqf data.rate_limit_burst)" "25/50"

printf '%s' "$BODY" | mut ban_granularity=cidr16 -id -updated_at > /tmp/b1.json
check_err "拒绝非法 ban_granularity" \
  "$(get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/b1.json | jqf error)" "封禁粒度"
printf '%s' "$BODY" | mut window_seconds=0 -id -updated_at > /tmp/b2.json
check_err "拒绝非法 window_seconds" \
  "$(get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/b2.json | jqf error)" "统计窗口"
printf '%s' "$BODY" | mut fail_mode=maybe -id -updated_at > /tmp/b3.json
check_err "拒绝非法 fail_mode" \
  "$(get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/b3.json | jqf error)" "fail_mode"
printf '%s' "$BODY" | mut geoip_mode=banall -id -updated_at > /tmp/b4.json
check_err "拒绝非法 geoip_mode" \
  "$(get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/b4.json | jqf error)" "地域模式"
R=$(printf '%s' "$BODY" | mut geoip_block_countries=us,ru,cn -id -updated_at > /tmp/m4.json; \
    get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/m4.json)
check "国家码规范化为大写" "$(printf '%s' "$R" | jqf data.geoip_block_countries)" "US,RU,CN"

echo
echo "########## 5. GeoIP ##########"
GS=$(get -H "$AUTH" "$BASE/api/v1/geoip/status")
check_ok "数据目录" "$(printf '%s' "$GS" | jqf data.data_dir)"
check "数据库均未加载时的加载标志" \
  "$(printf '%s' "$GS" | jqf data.country_loaded)/$(printf '%s' "$GS" | jqf data.city_loaded)/$(printf '%s' "$GS" | jqf data.region_loaded)" \
  "false/false/false"
GC=$(get -H "$AUTH" "$BASE/api/v1/geoip/countries")
CNT=$(printf '%s' "$GC" | jqf data.countries | tr -d '[]')
if [ "$CNT" -gt 100 ] 2>/dev/null; then
  printf '  %s %-44s %s 个国家/地区\n' "$(green PASS)" "国家列表已生成" "$CNT"; PASS=$((PASS + 1))
else
  printf '  %s %-44s %s\n' "$(red FAIL)" "国家列表已生成" "$CNT"; FAIL=$((FAIL + 1))
fi
check "属地库可用性（未加载时为 false）" "$(printf '%s' "$GC" | jqf data.available)" "false"
R=$(get -X POST "$BASE/api/v1/geoip/lookup" -H "$AUTH" -H 'Content-Type: application/json' -d '{"ip":"8.8.8.8"}')
check "属地查询回显 IP" "$(printf '%s' "$R" | jqf data.geoip.ip)" "8.8.8.8"
check "未加载库时 found=false" "$(printf '%s' "$R" | jqf data.geoip.found)" "false"
check "属地查询同时返回拦截状态" "$(printf '%s' "$R" | jqf data.state.valid)" "true"

echo
echo "########## 6. frp 接入 ##########"
SN=$(get -H "$AUTH" "$BASE/api/v1/frps/snippet")
check "插件监听地址" "$(printf '%s' "$SN" | jqf data.addr)" "127.0.0.1:9100"
check "插件路径" "$(printf '%s' "$SN" | jqf data.path)" "/frps/handler"
check "订阅 2 个 op" "$(printf '%s' "$SN" | jqf data.ops)" "[2]"
check_err "片段包含 httpPlugins" "$(printf '%s' "$SN" | jqf data.snippet)" "httpPlugins"
check_err "片段包含 ops" "$(printf '%s' "$SN" | jqf data.snippet)" 'ops = ["Login", "NewUserConn"]'
check_err "片段插件名正确" "$(printf '%s' "$SN" | jqf data.snippet)" 'name = "frpfirewall"'
# Ping 绝不能出现在 ops 里：每客户端 30s 心跳会成倍放大插件调用量。
# 只看 ops 行，片段正文里的说明性注释允许提到 Ping。
if printf '%s' "$SN" | jqf data.snippet | grep '^ops = ' | grep -q 'Ping'; then
  printf '  %s %-44s 片段 ops 中出现了 Ping\n' "$(red FAIL)" "ops 不含 Ping"; FAIL=$((FAIL + 1))
else
  printf '  %s %-44s 确认无 Ping\n' "$(green PASS)" "ops 不含 Ping"; PASS=$((PASS + 1))
fi
check "warnings 有 3 条" "$(printf '%s' "$SN" | jqf data.warnings)" "[3]"
check "插件 healthz" "$(get -o /dev/null -w '%{http_code}' "$PLUGIN/healthz")" "200"
FC=$(get -H "$AUTH" "$BASE/api/v1/frps/config")
check_err "加固配置含 tls.force" "$(printf '%s' "$FC" | jqf data.hardening)" "tls.force"
check "面板侧健康探测" "$(get -H "$AUTH" "$BASE/api/v1/frps/health" | jqf data.ok)" "true"

echo
echo "########## 7. 事件与规则变更（游标分页） ##########"
# 先造几条事件，才有数据验证翻页
for i in 1 2 3 4 5 6; do
  post_op Login "$(login_body "evt-$i" "203.0.113.$i:5000")" > /dev/null
done

EV=$(get -H "$AUTH" "$BASE/api/v1/events?limit=5&hours=24")
check "首页取 5 条" "$(printf '%s' "$EV" | jqf data.items)" "[5]"
check "还有更多数据" "$(printf '%s' "$EV" | jqf data.has_more)" "true"
check_ok "事件 total" "$(printf '%s' "$EV" | jqf data.total)"
CUR=$(printf '%s' "$EV" | jqf data.next_cursor)
# 第二页首条的 id 必须小于游标，否则两页内容会重叠
NEXT_FIRST=$(get -H "$AUTH" "$BASE/api/v1/events?limit=5&cursor=$CUR" | jqf data.items.0.id)
if [ -n "$CUR" ] && [ -n "$NEXT_FIRST" ] && [ "$NEXT_FIRST" -lt "$CUR" ] 2>/dev/null; then
  printf '  %s %-44s 游标 %s → 次页首条 %s\n' "$(green PASS)" "游标翻页不重叠" "$CUR" "$NEXT_FIRST"; PASS=$((PASS + 1))
else
  printf '  %s %-44s 游标 %s → 次页首条 %s\n' "$(red FAIL)" "游标翻页不重叠" "$CUR" "$NEXT_FIRST"; FAIL=$((FAIL + 1))
fi
check_ok "按类别过滤 login_blocked" "$(get -H "$AUTH" "$BASE/api/v1/events?limit=5&category=login_blocked" | jqf data.total)"
check_ok "关键字过滤" "$(get -H "$AUTH" "$BASE/api/v1/events?limit=5&keyword=203.0.113" | jqf data.total)"
check_any "规则变更审计 total" "$(get -H "$AUTH" "$BASE/api/v1/events/changes?page=1&size=5" | jqf data.total)"
ES=$(get -H "$AUTH" "$BASE/api/v1/events/stats?hours=24")
# 此处还没造出被拦截的事件（第 11 节才有），trend/top 必须是空数组而不是 null
check_list "统计 trend 为空数组" "$(printf '%s' "$ES" | jqf data.trend)"
check_list "统计 top_ips 为空数组" "$(printf '%s' "$ES" | jqf data.top_ips)"
check_list "统计 top_countries 为空数组" "$(printf '%s' "$ES" | jqf data.top_countries)"

echo
echo "########## 8. 系统与防火墙 ##########"
SI=$(get -H "$AUTH" "$BASE/api/v1/system/info")
check "版本号与 VERSION 一致" "$(printf '%s' "$SI" | jqf data.version)" "$EXPECT_VERSION"
check "面板监听" "$(printf '%s' "$SI" | jqf data.panel_listen)" "127.0.0.1:7930"
check "插件监听" "$(printf '%s' "$SI" | jqf data.plugin_listen)" "127.0.0.1:9100"
check "受保护 bind_port" "$(printf '%s' "$SI" | jqf data.bind_port)" "7000"
check "受保护 proxy_ports 2 个" "$(printf '%s' "$SI" | jqf data.proxy_ports)" "[2]"
check "引擎已启用" "$(printf '%s' "$SI" | jqf data.guard.enabled)" "true"
check "探测报告 arch" "$(printf '%s' "$SI" | jqf data.detect.arch)" "amd64"
check_ok "探测报告 os_pretty" "$(printf '%s' "$SI" | jqf data.detect.os_pretty)"
check_any "探测建议后端" "$(printf '%s' "$SI" | jqf data.detect.recommended)"
check "无后端时 managed 规则报错" \
  "$(get -H "$AUTH" "$BASE/api/v1/firewall/managed" | jqf error)" "当前没有可用的防火墙后端"
check "系统探测接口" "$(get -H "$AUTH" "$BASE/api/v1/system/detect" | jqf data.arch)" "amd64"

echo
echo "########## 8b. 系统配置（存于 SQLite） ##########"
CFG=$(get -H "$AUTH" "$BASE/api/v1/config")
# 注意取的是 data.config，不是 data 本身。
# PUT 的 body 直接绑定到 config.Config，顶层键必须与它的 json tag 对齐；
# 若误取外层 data（含 config/restart_required/data_dir），
# 回填时 guard / update / log 都会变成零值，等于把配置悄悄清空。
CFGBODY=$(printf '%s' "$CFG" | jqf data.config)
check "面板监听读自数据库" "$(printf '%s' "$CFG" | jqf data.config.server.listen)" "127.0.0.1:7930"
check "插件监听读自数据库" "$(printf '%s' "$CFG" | jqf data.config.frps.plugin_listen)" "127.0.0.1:9100"
check "数据目录回显" "$(printf '%s' "$CFG" | jqf data.data_dir)" "testdata/data"
check "当前无待生效改动" "$(printf '%s' "$CFG" | jqf data.restart_required)" "false"

# 改一项后应如实提示"需要重启"，而不是假装热更新成功
printf '%s' "$CFGBODY" | mut log.level=debug > /tmp/cfg1.json
R=$(get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg1.json)
check "改动后提示需重启" "$(printf '%s' "$R" | jqf data.restart_required)" "true"
check "配置项已落库" "$(get -H "$AUTH" "$BASE/api/v1/config" | jqf data.config.log.level)" "debug"

# 非法值必须被拦下：插件监听到外网会直接暴露无鉴权的接口
printf '%s' "$CFGBODY" | mut frps.plugin_listen=0.0.0.0:9100 > /tmp/cfg2.json
check_err "插件监听非回环被拒" \
  "$(get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg2.json | jqf error)" "回环"
printf '%s' "$CFGBODY" | mut 'frps.trusted_proxies=["not-a-cidr"]' > /tmp/cfg3.json
check_err "非法 CIDR 被拒" \
  "$(get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg3.json | jqf error)" "CIDR"

printf '%s' "$CFGBODY" > /tmp/cfg0.json
get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg0.json > /dev/null
check "配置已还原" \
  "$(get -H "$AUTH" "$BASE/api/v1/config" | jqf data.config.log.level)" \
  "$(printf '%s' "$CFG" | jqf data.config.log.level)"
# 回归守卫：PUT 的 body 必须是完整配置。曾经因为误取外层 data，
# 回填时把 guard/update 等没出现在 body 里的段全写成了零值。
check "回填未清空防护总开关" \
  "$(get -H "$AUTH" "$BASE/api/v1/config" | jqf data.config.guard.enabled)" \
  "$(printf '%s' "$CFGBODY" | jqf guard.enabled)"
check "回填未清空更新检查开关" \
  "$(get -H "$AUTH" "$BASE/api/v1/config" | jqf data.config.update.enabled)" \
  "$(printf '%s' "$CFGBODY" | jqf update.enabled)"

echo
echo "########## 8c. 版本与更新检查 ##########"
INFO=$(get -H "$AUTH" "$BASE/api/v1/system/info")
BINVER=$(printf '%s' "$INFO" | jqf data.version)
check_ok "运行版本号非空" "$BINVER"
# 只接受 0.0.1 或 0.0.1-pre.01 两种形态，别让 -dev 这类混进来
check "版本号格式合法" \
  "$(printf '%s' "$BINVER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-pre\.[0-9]{2,})?$' && echo ok || echo bad)" "ok"
check_ok "version_full 带提交号" "$(printf '%s' "$INFO" | jqf data.version_full)"
check "is_prerelease 是布尔" \
  "$(case "$(printf '%s' "$INFO" | jqf data.is_prerelease)" in true|false) echo ok ;; *) echo bad ;; esac)" "ok"
check "系统信息含 update.enabled" "$(printf '%s' "$INFO" | jqf data.update.enabled)" "true"

# 只读缓存的接口：没检查过时不应该凭空造一个 result 出来给前端渲染
UP=$(get -H "$AUTH" "$BASE/api/v1/system/update")
check "更新检查默认开启" "$(printf '%s' "$UP" | jqf data.enabled)" "true"
check "检查源为默认仓库" "$(printf '%s' "$UP" | jqf data.repo)" "dreamstation625/FrpFireWall"

# 主动检查：会真实联网。服务器访问不了 GitHub 时接口必须如实返回 error
# 而不是崩掉或假装成功，所以下面只对「结构」做强断言，连通性相关的断言按需放宽。
CHK=$(curl -s -S --noproxy '*' -m 40 -X POST "$BASE/api/v1/system/update/check" \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"force":true}')
check "检查已执行" "$(printf '%s' "$CHK" | jqf data.checked)" "true"
check "结果回显当前版本" "$(printf '%s' "$CHK" | jqf data.result.current)" "$BINVER"
check "结果回显检查源" "$(printf '%s' "$CHK" | jqf data.result.repo)" "dreamstation625/FrpFireWall"
check_err "给出 GitHub 发布页链接" \
  "$(printf '%s' "$CHK" | jqf data.result.releases_url)" "github.com/dreamstation625/FrpFireWall/releases"
check "has_update 是布尔" \
  "$(case "$(printf '%s' "$CHK" | jqf data.result.has_update)" in true|false) echo ok ;; *) echo bad ;; esac)" "ok"
# 列表字段必须是数组，不能是 null，否则前端要处处 || []
check_list "下载资源是数组而非 null" "$(printf '%s' "$CHK" | jqf data.result.assets)"

# 空 body 也要能走通：前端自动检查时不带任何参数
CHK2=$(curl -s -S --noproxy '*' -m 40 -X POST "$BASE/api/v1/system/update/check" \
  -H "$AUTH" -H 'Content-Type: application/json' -d '')
check "空 body 不报错" "$(printf '%s' "$CHK2" | jqf data.checked)" "true"
# 手动连点由服务端最小间隔兜住，必须命中缓存而不是又打一次 GitHub
check "紧接的第二次调用走缓存" "$(printf '%s' "$CHK2" | jqf data.result.from_cache)" "true"

CHK_ERR=$(printf '%s' "$CHK" | jqf data.result.error)
if [ -z "$CHK_ERR" ] || [ "$CHK_ERR" = "undefined" ] || [ "$CHK_ERR" = "null" ]; then
  if [ "$(printf '%s' "$CHK" | jqf data.result.has_update)" = "true" ]; then
    check_ok "判定有更新时给出最新版本号" "$(printf '%s' "$CHK" | jqf data.result.latest)"
  else
    check "无更新时 latest 回落为当前版本" \
      "$(printf '%s' "$CHK" | jqf data.result.latest)" "$BINVER"
  fi
  printf '  %s %-44s 联网正常\n' "$(green PASS)" "在线检查链路"; PASS=$((PASS + 1))
else
  # 离线环境（内网 / 被墙）属预期，不算失败，但要说清楚
  printf '  %s %-44s %s\n' "$(green PASS)" "离线时如实返回错误" "$CHK_ERR"
  PASS=$((PASS + 1))
fi

# 仓库名会被拼进 GitHub API 的 URL 路径，必须挡住越界字符
printf '%s' "$CFGBODY" | mut update.repo=../../etc/passwd > /tmp/cfg_up1.json
check_err "非法更新检查仓库被拒" \
  "$(get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg_up1.json | jqf error)" "owner/name"
printf '%s' "$CFGBODY" | mut 'update.repo=no-slash' > /tmp/cfg_up2.json
check_err "缺少 owner 的仓库名被拒" \
  "$(get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg_up2.json | jqf error)" "owner/name"

# 关掉开关后接口应如实回答未启用，而不是继续联网
printf '%s' "$CFGBODY" | mut update.enabled=false > /tmp/cfg_up3.json
R=$(get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg_up3.json)
check "关闭在线检查已落库" "$(printf '%s' "$R" | jqf data.restart_required)" "true"

printf '%s' "$CFGBODY" > /tmp/cfg_up0.json
get -X PUT "$BASE/api/v1/config" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/cfg_up0.json > /dev/null
check "更新检查配置已还原" \
  "$(get -H "$AUTH" "$BASE/api/v1/config" | jqf data.config.update.repo)" "dreamstation625/FrpFireWall"

echo
echo "########## 9. 黑白名单 ##########"
BEFORE=$(get -H "$AUTH" "$BASE/api/v1/acl/white?page=1&size=5" | jqf data.total)
# 去掉非数字字符再兜底成 0：接口异常时 jqf 会吐 PARSE_ERR，
# 直接丢进 $((BEFORE + 1)) 会被当成变量名，在 set -u 下把整个脚本带崩，
# 连失败汇总都打不出来。这里降级成 0，让断言自己 FAIL，能正常收敛。
BEFORE=${BEFORE//[!0-9]/}
: "${BEFORE:=0}"
NEW=$(get -X POST "$BASE/api/v1/acl/white" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"target":"203.0.113.7","remark":"冒烟测试"}')
check "新增白名单条目" "$(printf '%s' "$NEW" | jqf data.target)" "203.0.113.7"
check "自动识别类型 ipv4" "$(printf '%s' "$NEW" | jqf data.target_type)" "ipv4"
check "白名单总数 +1" "$(get -H "$AUTH" "$BASE/api/v1/acl/white?page=1&size=5" | jqf data.total)" "$((BEFORE + 1))"
check_err "非法地址被拒" \
  "$(get -X POST "$BASE/api/v1/acl/black" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"not-an-ip"}' | jqf error)" "非法的 IP"
ID=$(printf '%s' "$NEW" | jqf data.id)
check "删除白名单条目" "$(get -X DELETE "$BASE/api/v1/acl/white/$ID" -H "$AUTH" | jqf data.message)" "已删除"
CIDR=$(get -X POST "$BASE/api/v1/acl/black" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"198.51.100.5/24"}')
check "CIDR 被规范化为网络地址" "$(printf '%s' "$CIDR" | jqf data.target)" "198.51.100.0/24"
check "CIDR 类型识别" "$(printf '%s' "$CIDR" | jqf data.target_type)" "cidr4"
get -X DELETE "$BASE/api/v1/acl/black/$(printf '%s' "$CIDR" | jqf data.id)" -H "$AUTH" > /dev/null
IMP=$(get -X POST "$BASE/api/v1/acl/black/import" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"content":"198.51.100.0/24,机房\n# 注释行\nbad-input\n198.51.100.0/24,重复项","dry_run":true}')
check "导入 dry_run 去重: added" "$(printf '%s' "$IMP" | jqf data.added)" "1"
check "导入 dry_run 去重: skipped" "$(printf '%s' "$IMP" | jqf data.skipped)" "2"
check "导入 dry_run 标记" "$(printf '%s' "$IMP" | jqf data.dry_run)" "true"
check "非法行被记录" "$(printf '%s' "$IMP" | jqf data.invalid)" "[1]"
check "导出白名单" "$(get -o /dev/null -w '%{http_code}' -H "$AUTH" "$BASE/api/v1/acl/white/export")" "200"

echo
echo "########## 10. 封禁 ##########"
check_any "活跃封禁列表" "$(get -H "$AUTH" "$BASE/api/v1/bans/active" | jqf data.total)"
check_any "封禁历史 total" "$(get -H "$AUTH" "$BASE/api/v1/bans?page=1&size=5" | jqf data.total)"
check_err "内网地址不可封禁" \
  "$(get -X POST "$BASE/api/v1/bans" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"192.168.1.5","duration_sec":60}' | jqf error)" "系统保护"
check_err "回环地址不可封禁" \
  "$(get -X POST "$BASE/api/v1/bans" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"127.0.0.1","duration_sec":60}' | jqf error)" "系统保护"
BAN=$(get -X POST "$BASE/api/v1/bans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"target":"203.0.113.99","reason":"冒烟测试","duration_sec":120}')
check "手动封禁写入 /32" "$(printf '%s' "$BAN" | jqf data.target)" "203.0.113.99/32"
check "封禁状态 active" "$(printf '%s' "$BAN" | jqf data.status)" "active"
LK=$(get -X POST "$BASE/api/v1/bans/lookup" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"203.0.113.99"}')
check "排障查询 banned" "$(printf '%s' "$LK" | jqf data.banned)" "true"
check "排障查询窗口计数存在" "$(printf '%s' "$LK" | jqf data.window_hits)" "0"
check "排障查询系统保护" "$(printf '%s' "$LK" | jqf data.system_protected)" "false"
BID=$(printf '%s' "$BAN" | jqf data.id)
check "解封" "$(get -X DELETE "$BASE/api/v1/bans/$BID" -H "$AUTH" | jqf data.message)" "已解封"
check "解封后查询 banned=false" \
  "$(get -X POST "$BASE/api/v1/bans/lookup" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"203.0.113.99"}' | jqf data.banned)" "false"

echo
echo "########## 11. frps 插件回调 ##########"
R=$(post_op Login "$(login_body r1 8.8.8.8:5000)")
check "普通 IP 放行" "$(printf '%s' "$R" | jqf reject)" "false"
check "放行响应带 unchange=true" "$(printf '%s' "$R" | jqf unchange)" "true"
# 白名单必须先加再测，否则测到的只是「普通 IP 放行」
WID=$(get -X POST "$BASE/api/v1/acl/white" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"203.0.113.7","remark":"smoke-white"}' | jqf data.id)
R=$(post_op Login "$(login_body r2 203.0.113.7:5000)")
check "白名单 IP 放行" "$(printf '%s' "$R" | jqf reject)" "false"
get -X DELETE "$BASE/api/v1/acl/white/$WID" -H "$AUTH" > /dev/null

BID2=$(get -X POST "$BASE/api/v1/acl/black" -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"198.51.100.77","remark":"smoke-black"}' | jqf data.id)
R=$(post_op Login "$(login_body r3 198.51.100.77:5000)")
check "黑名单 IP 被拦" "$(printf '%s' "$R" | jqf reject)" "true"
check "拦截原因" "$(printf '%s' "$R" | jqf reject_reason)" "IP 已在黑名单中"
# 拒绝响应里不应带 unchange（结构体上是 omitempty，false 会被省略）
check "拒绝响应不带 unchange" "$(printf '%s' "$R" | jqf unchange)" "undefined"
R=$(post_op NewUserConn '{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"web","proxy_type":"tcp","remote_addr":"198.51.100.88:6000","local_addr":"127.0.0.1:80","user":""}}')
check "NewUserConn 回调响应" "$(printf '%s' "$R" | jqf reject)" "false"
check "Ping 直接放行" "$(post_op Ping '{"version":"0.1.0","op":"Ping","content":{}}' | jqf reject)" "false"
check "未知 op 放行（不阻断）" "$(post_op Unknown '{"version":"0.1.0","op":"Unknown","content":{}}' | jqf reject)" "false"
check "空 body 不 panic" "$(get -o /dev/null -w '%{http_code}' -X POST "$PLUGIN/frps/handler?op=Login" -H 'Content-Type: application/json' -d '')" "200"

# 上面刚拦掉 198.51.100.77，统计必须同步出数（第 7 节时这里还是空数组）
ES2=$(get -H "$AUTH" "$BASE/api/v1/events/stats?hours=24")
check_list_nonempty "拦截后 trend 非空" "$(printf '%s' "$ES2" | jqf data.trend)"
check_list_nonempty "拦截后 top_ips 非空" "$(printf '%s' "$ES2" | jqf data.top_ips)"
check_err "top_ips 含本轮被拦 IP" "$(printf '%s' "$ES2" | jqf data)" "198.51.100.77"

echo
echo "########## 12. 频次拦截与阶梯封禁 ##########"
# 用每轮唯一的 IP，否则上一轮留下的封禁历史会让本轮直接跳到第 2 级阶梯
FIP="198.51.100.$(( ($(date +%s) % 180) + 20 ))"
echo "  本轮测试 IP = $FIP"
printf '%s' "$BODY" | mut threshold=5 window_seconds=60 auto_ban_enabled=true observe_only=false \
  ban_durations=120,300 -id -updated_at > /tmp/f1.json
R=$(get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/f1.json)
check "阈值已改为 5" "$(printf '%s' "$R" | jqf data.threshold)" "5"
check "阶梯已改为 120,300" "$(printf '%s' "$R" | jqf data.ban_durations)" "120,300"

BLOCKED=0
for i in $(seq 1 9); do
  R=$(post_op Login "$(login_body "burst-$i" "$FIP:7000")")
  [ "$(printf '%s' "$R" | jqf reject)" = "true" ] && BLOCKED=$((BLOCKED + 1))
done
if [ "$BLOCKED" -ge 3 ]; then
  printf '  %s %-44s 9 次中 %s 次被拦\n' "$(green PASS)" "超阈值后被拦截" "$BLOCKED"; PASS=$((PASS + 1))
else
  printf '  %s %-44s 9 次中仅 %s 次被拦\n' "$(red FAIL)" "超阈值后被拦截" "$BLOCKED"; FAIL=$((FAIL + 1))
fi
LK=$(get -X POST "$BASE/api/v1/bans/lookup" -H "$AUTH" -H 'Content-Type: application/json' -d "{\"target\":\"$FIP\"}")
check "频次触发后已封禁" "$(printf '%s' "$LK" | jqf data.banned)" "true"
check "封禁原因为频次超限" "$(printf '%s' "$LK" | jqf data.ban.source)" "auto"
BL=$(get -H "$AUTH" "$BASE/api/v1/bans?page=1&size=5&keyword=$FIP")
check "产生封禁历史记录" "$(printf '%s' "$BL" | jqf data.items.0.source)" "auto"
check "全新地址首次触发为第 1 级" "$(printf '%s' "$BL" | jqf data.items.0.hit_count)" "1"
BID3=$(printf '%s' "$BL" | jqf data.items.0.id)
get -X DELETE "$BASE/api/v1/bans/$BID3" -H "$AUTH" > /dev/null
check "解封后 banned=false" \
  "$(get -X POST "$BASE/api/v1/bans/lookup" -H "$AUTH" -H 'Content-Type: application/json' -d "{\"target\":\"$FIP\"}" | jqf data.banned)" "false"

echo
echo "########## 13. 观察模式 ##########"
FIP2="198.51.100.$(( ($(date +%s) % 180) + 20 ))"
[ "$FIP2" = "$FIP" ] && FIP2="198.51.101.$(( ($(date +%s) % 180) + 20 ))"
printf '%s' "$BODY" | mut threshold=2 observe_only=true ban_durations=120 -id -updated_at > /tmp/f2.json
R=$(get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/f2.json)
check "观察模式已开启" "$(printf '%s' "$R" | jqf data.observe_only)" "true"
check "阈值已改为 2" "$(printf '%s' "$R" | jqf data.threshold)" "2"
for i in $(seq 1 6); do post_op Login "$(login_body "obs-$i" "$FIP2:7000")" > /dev/null; done
check "观察模式下不封禁" \
  "$(get -X POST "$BASE/api/v1/bans/lookup" -H "$AUTH" -H 'Content-Type: application/json' -d "{\"target\":\"$FIP2\"}" | jqf data.banned)" "false"
check "观察模式下窗口计数仍在累计" \
  "$(get -X POST "$BASE/api/v1/bans/lookup" -H "$AUTH" -H 'Content-Type: application/json' -d "{\"target\":\"$FIP2\"}" | jqf data.window_hits)" "6"

echo
echo "########## 14. 清理与恢复 ##########"
get -X DELETE "$BASE/api/v1/acl/black/$BID2" -H "$AUTH" > /dev/null
printf '%s' "$BODY" | mut -id -updated_at > /tmp/restore.json
R=$(get -X PUT "$BASE/api/v1/policy" -H "$AUTH" -H 'Content-Type: application/json' -d @/tmp/restore.json)
check "阈值已还原" "$(printf '%s' "$R" | jqf data.threshold)" "$(printf '%s' "$BODY" | jqf threshold)"
check "阶梯已还原" "$(printf '%s' "$R" | jqf data.ban_durations)" "$(printf '%s' "$BODY" | jqf ban_durations)"
check "观察模式已还原" "$(printf '%s' "$R" | jqf data.observe_only)" "$(printf '%s' "$BODY" | jqf observe_only)"
check "速率限制已还原" "$(printf '%s' "$R" | jqf data.rate_limit_enabled)" "$(printf '%s' "$BODY" | jqf rate_limit_enabled)"

echo
echo "======================================================="
printf '通过 %s 项，失败 %s 项\n' "$(green "$PASS")" "$(red "$FAIL")"
[ "$FAIL" -eq 0 ] && echo "全部通过" || echo "存在失败项"
exit 0
