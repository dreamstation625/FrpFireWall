# FRP 服务端防火墙插件 — 设计方案

> 状态：待评审（评审通过后进入编码）
> 目标：给 frps 加一个可视化的防火墙/防爆破能力，支持 iptables 与 nftables 双后端、GeoIP 属地查询、频次拦截、黑白名单管理。

---

## 1. 目标与边界

### 1.1 做什么

| 能力 | 说明 |
|---|---|
| 防火墙模式切换 | 自动探测 + 手动指定 `iptables` / `nftables`，两套后端行为对齐 |
| 规则可视化 | 展示本程序受管规则 + 系统完整规则（只读），实时对比期望状态与实际状态 |
| frps 插件接入 | 以 frps `httpPlugins` 形式接入，在 `Login` / `NewUserConn` 阶段拦截 |
| 频次控制 | 滑动窗口统计失败次数，超阈值自动封禁，支持阶梯式递增封禁时长 |
| GeoIP | MaxMind GeoLite2 判国家/大洲（可拦截），ip2region 判国内省市（用于展示） |
| 黑白名单 | 手动增删改、批量导入导出、来源标记、到期时间 |
| frp 配置生成 | 前端直接给出需要追加到 `frps.toml` 的配置片段，可一键复制 |
| 事件与审计 | 登录失败、封禁、解封、规则变更全量留痕 |

### 1.2 不做什么（明确排除）

- **不支持 Docker / 容器环境**（按需求）。程序假定直接跑在宿主机上、直接操作宿主内核防火墙。
- 不做 frps 自身进程管理（不重启、不改 frps 主配置，只生成片段给用户手工粘贴）。
- 不做七层 WAF（HTTP 内容检测交给宝塔 WAF 等既有组件）。
- 不做多节点集群管理（见 §11.1）。当前按单机设计。

### 1.3 运行前提

- Linux 宿主机，root 或具备 `CAP_NET_ADMIN` + `CAP_NET_RAW`。
- 系统存在 `iptables`（含 `ip6tables`）或 `nftables`（版本 ≥ 0.9.3）之一。**不需要 ipset。**
- frps ≥ v0.44.0（`httpPlugins` 完整支持 `Login` / `NewUserConn`）。

---

## 2. 核心设计决策

> 这一节是方案的骨架，每一条都对应一个容易被忽略的坑。

### D1. 拦截分两层，各司其职

```
应用层（frps 插件）  →  精准、有上下文、能即时拒绝、能做阶梯封禁
网络层（iptables/nft）→  持久、能兜住非 frp 协议流量、重启后仍生效
```

单靠任一层都有洞：

- 只做应用层：攻击者仍可疯狂连 `bindPort` 消耗连接资源（插件只在 frp 协议握手后才被调用，纯 TCP 扫描不会触发插件）。
- 只做网络层：拿不到 `user` / `run_id` / CDN 真实访客 IP，只能按裸 IP 一刀切，误伤率高。

所以：**插件层做决策，网络层做落地。**

### D2. 受管规则独立成链/表，绝不 flush 整表

这是最要命的一条。程序只在**自己的命名空间**内增删规则：

| 后端 | 独占命名空间 |
|---|---|
| iptables | 两条自定义链：`FRPFIREWALL_GUARD`（主链）+ `FRPFIREWALL_BLACK`（黑名单子链） |
| nftables | 集合 `frpfirewall_black` / `frpfirewall_black6` / `frpfirewall_rate`；规则靠 `comment "frpfirewall:*"` 标记归属 |

只在 `INPUT` 链首插一条 `-j FRPFIREWALL_GUARD` 跳转。nftables 侧**不建自己的 base chain**，
而是把规则 `insert` 到系统已有的 input 链最前面（原因见 D3）。
**任何情况下都不执行 `iptables -F` / `nft flush ruleset`。** 用户已有的 ufw / firewalld / 宝塔规则不受影响。

### D3. 白名单是"豁免封禁"，不是"全端口放行"

常见的错误做法：把白名单 IP 在 `INPUT` 顶部 `ACCEPT`。这会让被白名单的 IP **绕过系统所有既有安全规则**，拿到全端口访问权，等于开后门。

本项目的白名单**不往内核写任何规则**：语义是"豁免本程序的封禁"，所以在上层生成黑名单时
把白名单地址减掉即可，效果完全等价，同时避开了 `return` verdict 在不同链路上下文里的歧义。

iptables 侧的受管结构：

```
INPUT ─(第1条)─▶ FRPFIREWALL_GUARD
                   ├─ -j FRPFIREWALL_BLACK     ← 固定跳转到黑名单子链
                   ├─ [限速规则]               ← 可选
                   └─ -j RETURN
FRPFIREWALL_BLACK
                   └─ -s <黑名单> -j DROP      ← 逐条
```

黑名单单独放一个子链，是因为增量封禁/解封是高频操作：写在主链里每次都要算"插到第几条"、
还要处理删除后的序号漂移；放进子链后追加就是 `-A`、删除就是按内容 `-D`，完全不依赖位置。

nftables 侧**不建自己的 hook 链**：同一 hook 上多个 base chain 按 priority 依次执行，
一条 `policy accept` 的链放在后面，判决会被前面的链吃掉，直接毁掉系统原有规则。
正确做法是把规则 `insert` 到系统已有 input 链的最前面，链内只用 `drop`，不匹配就自然往下走。

### D4. 期望状态驱动，而不是散落的 add/delete

所有防火墙变更走同一条 **reconcile 回路**：

```
内存中的 BanSet（唯一权威）
      ↓ 生成期望状态
 期望规则集（纯数据结构，可 diff）
      ↓ diff
 实际规则集（从 iptables-save / nft -a list 解析得到）
      ↓
 最小变更集（只 add/delete 差异部分）
```

好处：
- 程序重启、崩溃、被 kill 后，启动时一次 reconcile 即可自愈，不会残留脏规则。
- 手动用命令行改过防火墙也能被检测到并在 UI 上提示"配置漂移"。
- 幂等，重复执行无副作用。

### D5. 写入前先 dry-run；自动回滚尚未接线

- nftables：所有变更先 `nft -c -f -` 做语法预检，通过后才正式提交。**已实现。**
- iptables：逐条执行，全部幂等（先 `-C` 判断存在再 `-A`，删除时先判断再删）。**已实现。**
- "变更前 `Snapshot()` 备份 → 应用后健康检查 → 失败自动 `Restore()`"这条回路，
  `Driver` 接口上已经有 `Snapshot` / `Restore` 两个方法，但**自动回滚还没有接上**
  （`Restore` 目前没有任何调用点）。面板侧只用到 `GET /firewall/snapshot` 供人查看。
  因此误封 / 规则异常的兜底手段是 `frpfirewall-panic.sh`（见 §7.1），不要在文档上把它当成自动的。

### D6. 插件服务必须 fail-open，且绝不能挂 `Ping`

- frps 调用插件是**同步阻塞**的。插件卡住 = frps 登录卡住。
- 因此：插件内部只做纯内存判断（目标 P99 < 20ms），防火墙写入走异步队列（带重试），不阻塞响应。
- 插件自身异常/超时 → 返回"放行"，即 **fail-open**。理由：防火墙插件挂掉不应该导致整个 frp 服务不可用。（策略可配成 fail-close，默认 off）
- `ops` 只挂 `["Login", "NewUserConn"]`。**`Ping` 绝对不要挂** —— 它是每客户端每 30s 一次的心跳，挂上去会让插件 QPS 乘以客户端数，在 2C1G 的小机器上直接把 frps 拖死。

### D7. CDN 回源 IP 必须自动保护

架构是 `CDN → frps 回源`。`NewUserConn` 拿到的 `remote_addr` 很可能就是 **CDN 节点 IP**，而不是终端用户 IP。

如果按这个 IP 封禁，封掉一个 CDN 边缘节点 = 掐死一大片正常用户。

处理策略：
1. 内置主流 CDN 回源段白名单（Cloudflare / 腾讯 EdgeOne / 百度云加速，可持续更新），命中则**永不封禁**。
2. 优先从 `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` 取真实客户端 IP，封这个 IP 而不是回源 IP。
3. UI 上对"回源节点封禁"二次确认。

### D8. 不问 ipset，属地只在 IP 访问时实时解析

**约束（来自需求澄清）：不使用 ipset 这类内核集合来存地区。**

一个国家的 CIDR 动辄几千条（中国 IPv4 段超 8000 条），如果按「国家 → 展开成 CIDR → 灌进内核」
的思路做，无论用 ipset 还是逐条 `-s x.x.x.x/24 -j DROP`，都会让规则链膨胀到无法维护。

所以反过来做：**GeoIP 只在应用层参与判定，不下沉到内核。**

- 插件回调（`Login` / `NewUserConn`）拿到 IP 的那一刻，直接查内存里的属地库。
  mmdb 是内存映射 + 二分查找，ip2region 是内存索引，都是微秒级，不构成瓶颈。
- 命中国家封禁策略时，产生的是**这次连接被拒绝**，而不是往内核里灌几千条 CIDR。
- 只有「针对具体 IP 的封禁记录」才会进内核黑名单，条数天然有界（受封禁记录数约束）。

nftables 侧仍然使用集合（`frpfirewall_black` + `flags interval`），但那是**本项目自己的封禁地址集合**，
用来把 CIDR 封禁写成一条规则而不是 N 条，跟「用集合存地区」是两件事。

iptables 侧不引入 ipset，改用独立黑名单子链逐条 `-A`。
封禁条数由策略控制，属于可接受范围；真要上千条时优先引导用户切到 nftables 后端。

### D9. 版本号只有两种形态，且正式版不追预发布

版本号采用语义化版本的一个**子集**，只允许两种写法：

| 形态 | 例子 |
|---|---|
| 正式版 | `0.0.1` |
| 预发布版 | `0.0.1-pre.01` |

不接受 `-dev` / `-rc.N` / `-alpha.N` / `-beta.N` 这类后缀，序号固定两位
（超过 99 自然进位为 `pre.100`）。范围收窄是刻意的：格式越少，
比较逻辑越不容易出错，CI 也才敢对 `VERSION` 文件做强校验。

**唯一来源是仓库根目录的 `VERSION` 文件。** 构建时经 `-ldflags -X` 注入二进制；
发布 tag 必须与它一致，由 CI 强制校验——否则会出现「tag 写着 0.0.2、
二进制里编译进去的却是 0.0.1」这种在面板上根本看不出来的事故。

#### 更新筛选：两条轨道互不跨越

这是本模块最核心的规则，由纯函数 `version.SelectUpdate` 承担：

| 当前版本 | 接受哪些更新 |
|---|---|
| 正式版 `0.0.1` | **只接受更高的正式版**，永不提示任何预发布版 |
| 预发布版 `0.0.1-pre.01` | 接受更高的任意版本：更高序号的预发布版，以及正式版 |

比较规则是标准的语义化版本加一条：**同一号段内正式版大于预发布版**
（`0.0.1 > 0.0.1-pre.99`）。因此预发布用户在同号正式版发布时会被推过去
（`0.0.1-pre.03` → `0.0.1`），而正式版用户完全看不到预发布版的存在。

这样设计的原因：正式版用户要的是稳定，把他引到 `-pre` 上是倒退；
而已经在预发布轨道上的用户，正式版一发出来就应该被推过去。

#### 检查更新的几个取舍

- **只读，不自动更新。** 自更新要替换正在运行的可执行文件、校验签名、失败回滚，
  风险与复杂度都远超收益。本程序只提示有新版本并给出下载链接，装不装由人决定。
- **匿名访问 GitHub API**，仓库为公开仓库，无需 token。
- **缓存一小时，失败缓存十分钟。** GitHub 匿名 API 限流按 IP 计（60 次/小时），
  而前端每次打开面板都会自动查一次；失败若不缓存，离线环境下就变成每次开面板都挂一个
  15 秒超时，把面板拖慢。手动点「检查更新」可绕过缓存（仅受 15 秒最小间隔约束），
  这样网络恢复后用户能立刻重试。
- **tag 解析失败只跳过，不整体失败。** GitHub 上难免有 `nightly` 这类非版本号 tag，
  跳过它们并记入 `skipped_tags`，便于排查而不影响主流程。
- **可关闭。** 纯内网或不允许出网的服务器可以在面板里关掉在线检查，
  此时界面仍显示当前版本与发布页链接。

#### 发布闸门：只有版本号提升才构建

`release.yml` 在校验完 tag 与 `VERSION` 一致之后、动任何构建之前，先做一次判定：
候选 tag 的版本必须**严格高于已发布 release 里的最高版本**，否则跳过整个构建与发布。

| 场景 | 判定 |
|---|---|
| 重复推送同一个 tag | 跳过 |
| 推出比线上更旧的版本 | 跳过（否则 latest 会被指回旧版本） |
| 正式版已发布后推同号 `-pre` | 跳过（`0.0.1-pre.02 < 0.0.1`，属倒退） |
| 发布失败后重跑同一个 tag | 发布 |

**基准取「已发布的 release」而不是 git tag**，这是这里唯一反直觉的地方：
tag 在 release 建成之前就已经存在。若拿 tag 当基准，「构建失败」或
「release 创建失败」之后重跑工作流时，本次 tag 已经在基准列表里，会被判成
「没有提升」而永远跳过——失败的发布就再也修不好了。改用已发布列表后自洽：
首发与失败重跑都算提升，只有真正发布过之后再重推才会跳过。

比较直接复用 `internal/version` 的 `Parse` / `Compare`（见 `tools/versioncmp`），
不在 CI 里另写一份。原因是这条规则有个容易写反的分支——**同号段正式版大于预发布版**
（`0.0.1 > 0.0.1-pre.99`）。用 shell 或 `sort -V` 手写几乎必错：

```console
$ printf '0.0.1\n0.0.1-pre.99\n' | sort -V
0.0.1            # ← sort 认为它更小
0.0.1-pre.99     # ← 而按本项目的语义，它更小
```

闸门判定为「不发布」时，工作流是**成功**状态而非失败：重推同一个 tag 是常见误操作，
不该把 CI 变红。判定依据会写进 step summary，避免「绿了但没发布」被误解。

### D10. 一键脚本自带版本比较，并用测试与 Go 侧钉死

`scripts/install.sh` 一个文件管三件事：`install` / `update` / `uninstall`（外加 `status`），
在线拉取 Release 而不是要求用户先下载好一堆文件。

**必须在脚本里重写一遍版本比较**，这是唯一的重复代码，理由是无法回避的：脚本要在
一台还没有 Go 工具链的机器上跑，`tools/versioncmp` 用不上。既然要重复，就用测试锁死一致：

- `testdata/test-install.sh` 把同一批用例同时喂给脚本里的 `vcmp` 与 `tools/versioncmp`，
  逐条断言判定相同；
- 非法输入（`-rc.1`、`1.2`、`pre.0`）要求两边一致拒绝。

这条守卫不是形式主义：一旦两边漂移，症状是「面板提示有新版本、一键脚本却说已是最新」，
而且只在特定版本组合下出现，靠人工点很难撞到。

其余取舍：

- **默认只走正式版轨道。** `update` 一律解析最新正式版；要预发布必须显式 `--pre`
  或 `-v 0.0.1-pre.01`。这与面板内「正式版不追预发布」的规则同源，只是更保守：
  预发布用户默认更新也会落到正式版上。
- **探测最新正式版不调 API。** 读 `releases/latest/download/<asset>` 的**第一跳**
  `Location` 就能拿到 tag。GitHub API 匿名限流 60 次/小时（按出口 IP 算），
  而下载链接走 CDN 不限流；装机脚本恰恰可能在 NAT 后面被跑很多次。
  不跟随重定向也有原因——跟到底会落到签名 CDN 地址，那里面已经没有 tag 了。
  只有 `--pre`（需要枚举全部 release）才走 API。
- **校验和覆盖全部下载物。** 发布时把二进制、服务单元、救援脚本、脚本自身一起算进
  `sha256sums.txt`，脚本逐个核对。二进制缺条目直接失败；辅助文件缺条目只警告——
  早期发布只覆盖了二进制，那种旧版本仍应装得上。
- **升级先下载、校验、再原子替换，最后才重启。** 换二进制前把旧的另存为 `.prev`，
  新版本起不来就换回去再重启一次。防火墙程序升级失败是直接掉防护，不能只留一句
  「启动失败」。
- **卸载默认保留数据目录**，`--purge` 才删，且删除前有多重护栏（系统目录黑名单、
  路径深度、目录内必须含 `frpfirewall.db`）。护栏在**动任何东西之前**执行——
  否则会出现「应用已经删掉了，才告诉你数据目录不许删」。
- **不内置任何第三方加速地址**，只提供 `--mirror <前缀>`。把用户流量导向不受控的
  中间人应该是用户的主动选择，不能是默认行为。
- **顺序要求**：卸载时先 `systemctl stop` 再清内核规则。进程还在跑的话，
  下一次 reconcile 会把刚清掉的规则重新下发。

---

## 3. 总体架构

```
┌──────────────────────────────────────────────────────────────┐
│  浏览器  Vue3 + Element Plus (Vite 构建, embed 进二进制)        │
└───────────────────────────┬──────────────────────────────────┘
                            │ REST /api/v1  (JWT)
┌───────────────────────────▼──────────────────────────────────┐
│  frpfirewall  (Go 单二进制, systemd)                                 │
│                                                              │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ API Layer  │  │ Guard Engine │  │ frps Plugin Server   │  │
│  │ Gin        │─▶│ 滑窗计数      │◀─│ POST /frps/handler   │  │
│  │ 静态资源    │  │ 封禁状态机    │  │ op=Login/NewUserConn │  │
│  └────────────┘  └──────┬───────┘  └──────────────────────┘  │
│         │               │                                    │
│  ┌──────▼───────────────▼───────┐  ┌──────────────────────┐  │
│  │ Reconcile Loop               │  │ GeoIP                │  │
│  │ 期望状态 ⇄ 实际状态           │  │ GeoLite2 + ip2region │  │
│  └──────┬───────────────────────┘  └──────────────────────┘  │
│         │                                                    │
│  ┌──────▼────────────────────────────────────────────────┐   │
│  │ Firewall Driver (接口抽象)                            │   │
│  │   ├─ iptables 驱动 (两条自定义链)                     │   │
│  │   └─ nftables 驱动 (集合+插入系统链)                  │   │
│  └──────┬────────────────────────────────────────────────┘   │
│         │                                                    │
│  ┌──────▼────────┐                                           │
│  │ SQLite        │ 策略/名单/封禁记录/事件审计                  │
│  └───────────────┘                                           │
└───────────────────────────┬──────────────────────────────────┘
                            │
                    ┌───────▼────────┐
                    │ 内核 netfilter │
                    └────────────────┘
                            ▲
                            │ httpPlugins RPC
                    ┌───────┴────────┐
                    │      frps      │◀── frpc 登录 / CDN 回源
                    └────────────────┘
```

---

## 4. 后端设计（Go）

### 4.1 技术栈

| 项 | 选型 | 理由 |
|---|---|---|
| 语言 | Go 1.26 | 单二进制，无运行时依赖 |
| Web 框架 | Gin | 中间件生态成熟（JWT/CORS/日志/恢复） |
| 配置 | SQLite 单表（`settings`） | **没有配置文件**，启动只需 `-data`；改配置走面板，不引入第二种配置语法 |
| 数据库 | SQLite via `glebarez/sqlite`（底层 `modernc.org/sqlite`） | **纯 Go 实现，免 CGO**，交叉编译单文件无障碍 |
| ORM | GORM | 自动 migration，模型即表结构 |
| 日志 | 标准库 `log/slog` | 零依赖，结构化输出够用 |
| 前端托管 | `embed.FS` | 前端产物打进二进制，部署就一个文件 |
| GeoIP | `oschwald/maxminddb-golang` + `lionsoul2014/ip2region` | 前者读 mmdb，后者读 xdb |
| 定时任务 | 标准库 `time.Ticker` | 只做封禁过期清理与 reconcile，不值得引入 cron |
| 版本号 | 自实现的极简语义化版本子集 | 只支持 `0.0.1` / `0.0.1-pre.01` 两种形态，几十行搞定，不引入 semver 库（它们不接受 `pre.01` 这种前导零写法） |
| 更新检查 | 标准库 `net/http` 直连 GitHub Releases API | 只读不下载，避免引入 github 客户端库 |

### 4.2 目录结构

```
FrpFireWall/
├── VERSION                    # 版本号唯一来源，CI 校验 tag 与它一致
├── cmd/frpfirewall/main.go    # 入口：建目录 → 开库 → 读配置 → 装配 → 起服务
├── internal/
│   ├── version/           # 版本号注入、解析、比较与更新筛选（含单元测试）
│   ├── update/            # GitHub Releases 更新检查（带缓存，只读，含单元测试）
│   ├── config/            # 配置模型 + SQLite 持久化（config.go / settings.go / password.go）
│   ├── model/             # 领域模型（ACL / 封禁 / 策略 / 事件 / 键值）
│   ├── store/             # GORM + 纯 Go SQLite 数据层
│   ├── firewall/
│   │   ├── driver.go      # Driver 接口 + 受管对象名常量
│   │   ├── detect.go      # 系统与后端探测
│   │   ├── iptables.go    # 两条自定义链实现
│   │   └── nftables.go    # 集合 + 插系统 input 链的实现
│   ├── guard/
│   │   ├── manager.go     # 引擎装配与 reconcile 循环
│   │   ├── window.go      # 滑动窗口计数
│   │   ├── judge.go       # 判定：白/黑名单、属地、频次
│   │   ├── ban.go         # 封禁状态机（阶梯时长、到期）
│   │   └── protect.go     # 自我保护名单（回环 / 内网 / 链路本地）
│   ├── geoip/
│   │   ├── geoip.go       # mmdb + xdb 双库查询与热加载
│   │   └── country.go     # 内置国家/地区中文名列表
│   ├── frpsplugin/
│   │   └── server.go      # frps httpPlugins 服务端 + 配置片段生成
│   ├── api/
│   │   ├── api.go         # 路由注册与鉴权中间件
│   │   ├── auth.go        # 登录 / 初始化 / 改密码
│   │   ├── handlers.go    # 系统、防火墙、frps、事件
│   │   ├── handlers_acl.go
│   │   ├── handlers_config.go
│   │   └── handlers_update.go   # 版本更新状态与主动检查
│   └── web/               # go:embed 前端产物 + SPA 回退
├── web/                   # Vue3 前端源码
├── tools/versioncmp/      # 发布闸门：候选版本是否高于已发布最高版本
├── testdata/              # 冒烟测试脚本与辅助工具
├── scripts/
│   ├── install.sh
│   └── frpfirewall-panic.sh     # 一键清空本程序规则（救援用）
├── .github/workflows/
│   ├── ci.yml             # 提交守门：版本格式、平台依赖、go vet、单元测试、前端构建
│   └── release.yml        # tag 触发：校验 → 发布闸门 → 构建 → 创建 Release
├── deploy/frpfirewall.service
└── docs/DESIGN.md
```

### 4.3 防火墙驱动抽象

```go
type Driver interface {
    Name() string                                  // "iptables" | "nftables"
    Detect() (Capability, error)                   // 后端可用性、版本、必备命令是否存在
    EnsureBase() error                             // 幂等创建链/表/set
    Snapshot() (Snapshot, error)                   // 全量快照（供回滚）
    Restore(Snapshot) error
    DryRun(patch Patch) error                      // 语法预检
    Apply(patch Patch) error                       // 原子应用最小变更集
    DumpManaged() (RuleSet, error)                 // 仅本程序受管规则（结构化）
    DumpSystem() (string, error)                   // 系统完整规则（原始文本，只读展示）
    // 名单操作
    AddElements(set string, items []string) error
    DelElements(set string, items []string) error
    ListElements(set string) ([]Element, error)
}
```

`Patch` 是纯数据结构（要增/删的 IP、CIDR、set 名），两个驱动各自翻译成自己的命令。上层业务代码完全不感知后端差异。

#### iptables 驱动的具体落地

```bash
# 基础结构（幂等，全部带 -w 拿 xtables 锁，避免与其它工具并发写）
iptables -w -N FRPFIREWALL_GUARD 2>/dev/null || true
iptables -w -N FRPFIREWALL_BLACK 2>/dev/null || true
iptables -w -C INPUT -j FRPFIREWALL_GUARD 2>/dev/null || iptables -w -I INPUT 1 -j FRPFIREWALL_GUARD

# 主链只负责分流，不承载具体 IP
iptables -w -A FRPFIREWALL_GUARD -j FRPFIREWALL_BLACK
iptables -w -A FRPFIREWALL_GUARD -j RETURN          # 限速规则存在时插在两者之间

# 封禁 / 解封：纯追加 + 按内容删除，不用关心位置
iptables -w -A FRPFIREWALL_BLACK -s 1.2.3.4 -j DROP
iptables -w -D FRPFIREWALL_BLACK -s 1.2.3.4 -j DROP
```

要点：
- **不引入 ipset。** 封禁条数由封禁记录数约束，属于可接受范围；真要上千条时优先引导用户切到 nftables 后端。
- 白名单不落内核（见 D3），所以链里没有白名单相关规则。
- IPv6 走 `ip6tables`，链名与结构完全相同。
- 若系统用的是 `iptables-nft`（nft 后端），照样可用，但注意与 nftables 驱动**不要同时启用**，UI 上互斥。

#### nftables 驱动的具体落地

```bash
# 集合建在自己的名字空间里，规则插进系统已有的 input 链。
# 下面是系统存在 inet/filter/input 的情形，实际 family/table/chain 由探测决定。
nft -f - <<'EOF'
add set inet filter frpfirewall_black  { type ipv4_addr; flags interval; }
add set inet filter frpfirewall_black6 { type ipv6_addr; flags interval; }
add set inet filter frpfirewall_rate   { type ipv4_addr; flags interval; }

insert rule inet filter input ip  saddr @frpfirewall_black  drop comment "frpfirewall:black"
insert rule inet filter input ip6 saddr @frpfirewall_black6 drop comment "frpfirewall:black6"
EOF
```

要点：
- **不建自己的 base chain**，只往系统已有链里插规则（原因见 D3）。
- 所有变更通过 `nft -f` 一次性提交，天然原子；提交前先用 `nft -c -f -` 做语法预检。
- 限速用集合 + `limit rate over N/second burst M packets`，需 nft ≥ 0.9.3。
- 规则归属靠 `comment` 标记识别；读回来时用 `nft -a list chain` 拿 handle，用 `nft -j list ruleset` 做集合探测。

#### 后端探测与切换（`支持多种系统`）

`detect.go` 的探测顺序：

1. 读 `/etc/os-release`（ID / VERSION_ID）→ 记录发行版。
2. 检查 `firewalld` 是否 active（`systemctl is-active firewalld`）：
   - 若 active 且用户选 iptables 模式 → **警告**：firewalld 会周期性 reload 并冲掉非受管规则，提供两个选项 ①改用 nftables 模式直连内核 ②走 `firewall-cmd --direct` 写规则（兼容但受限）。
3. 检查 `ufw` 是否 active：ufw 底层也是 iptables，本方案的独立链方案与之兼容，无需特殊处理，仅提示。
4. 检查 `nftables` 版本（`nft --version`）：**CentOS 7 自带 0.9.0，`flags interval` 等语法不可用** —— 低版本降级为非 interval set 或退回 iptables 模式。
5. 检查必备命令（`iptables` / `ip6tables` / `nft`）是否存在。**不检查 `ipset`** —— 本方案不用它（见 D8）。
6. 结果缓存，UI 的"防火墙模式"下拉框默认选中探测结果，用户可手动覆盖（覆盖值持久化）。
7. 切换模式时：先 `EnsureBase()` 新后端 → 迁移名单 → 再清理旧后端受管对象。**顺序不能反**，否则中间窗口无保护。

### 4.4 封禁引擎（Guard Engine）

```
                         ┌──────────────┐
  frps Login 事件 ──────▶│ 滑动窗口计数  │
  （失败/成功/未知用户）    └──────┬───────┘
                                 │ 超阈值
                                 ▼
                          ┌──────────────┐        ┌──────────┐
                          │ 封禁状态机    │───────▶│ BanSet   │
                          │ 阶梯时长计算  │        │ (内存权威)│
                          └──────────────┘        └────┬─────┘
                                                       │
                                          reconcile ───┘──▶ 防火墙
```

**滑动窗口计数**：`key = IP (+ 可选 user)`，`window` 与 `threshold` 可配（默认 60s / 10 次）。实现用分桶环形数组，内存 O(活跃 IP 数)，定期淘汰冷 key。

**封禁状态机**：

| 阶段 | 默认时长 |
|---|---|
| 首次触发 | 10 min |
| 窗口内（默认 24h）第二次 | 1 h |
| 第三次 | 24 h |
| 第四次及以后 | 永久（可配上限） |

计数窗口与递增倍率均可在前端配置。封禁对象支持 IP 与 /24 网段两个粒度（可配，默认单 IP，避免误伤整段）。

**解封**：到期由定时器（1s tick 或最小堆）驱动，从 BanSet 移除 → reconcile 同步到防火墙。

**手动封禁**与自动封禁统一进同一 BanSet，用 `source` 字段区分：`auto` / `manual` / `geoip`。手动封禁默认不自动过期（可设到期时间）。

**重放与自愈**：启动时读 SQLite 中 `status=active` 的封禁记录 → 重建 BanSet → 全量 reconcile。这样即使程序宕机期间被手工清了规则，重启也能恢复。

### 4.5 frps 插件服务

对接 frps 原生协议（JSON over HTTP）：

```
POST /frps/handler?version=0.1.0&op=Login
X-Frp-Reqid: <trace id>

{
  "version": "0.1.0",
  "op": "Login",
  "content": {
    "version": "0.61.0", "hostname": "...", "os": "linux", "arch": "amd64",
    "user": "alice", "timestamp": 1759...,
    "privilege_key": "...", "run_id": "...", "pool_count": 1,
    "metas": {},
    "client_address": "1.2.3.4:57123"     ← 关键：frpc 源地址
  }
}
```

响应：

```json
{ "reject": true,  "reject_reason": "IP banned until 2026-09-30T15:20:00+08:00" }
{ "reject": false, "unchange": true }
```

处理逻辑（纯内存，目标 P99 < 20ms）：

```
1. 解析 client_address → 拆出 IP
2. 命中系统保护名单 / 白名单？        → 放行（并记录）
3. 命中黑名单 / 封禁中？              → 拒绝（reason 带上剩余时间）
4. 命中 geoip 封禁国家？              → 拒绝 + 自动封禁
5. 查 GeoIP 属地，写入事件流（供前端展示）
6. 成功/失败计数入滑窗；超阈值          → 异步触发封禁 → 拒绝本次
7. 其余                               → 放行
```

要点：
- 服务只监听 `127.0.0.1:<port>`，不对外暴露；可选要求 `X-Frp-Plugin-Token` 头校验（frps 的 `httpPlugins` 不支持自定义 header，故实际以来源 IP 白名单 + 仅绑回环为准）。
- 处理函数外层套 `context.WithTimeout(100ms)`，超时/panic 一律 fail-open 放行（见 D6）。
- `NewUserConn` 走同一套逻辑，但**封禁决策必须区分回源 IP 与真实客户端 IP**（见 D7）。
- `ops = ["Login", "NewUserConn"]`，明确不含 `Ping`。

### 4.6 GeoIP 模块

| 用途 | 数据源 | 查询内容 |
|---|---|---|
| 国家/大洲封禁 | `GeoLite2-Country.mmdb`（~6MB） | ISO 国家码、大洲码 |
| 属地展示（国外） | `GeoLite2-City.mmdb`（~60MB，可选） | 国家/城市/经纬度 |
| 属地展示（国内） | `ip2region.xdb`（~11MB） | 省/市/运营商 |

- 查询走 mmap，微秒级，可同步调用。
- **库更新目前只有"手动上传"一条路径**：面板 **IP 属地** 页上传，后端先校验文件头再原子替换，
  立即热加载。自动下载（MaxMind 需账号且国内直连常失败）与 Cron 同步都还没做。
- **国家封禁只在应用层生效**（见 D8）：命中国家黑/白名单策略时拒绝这一次插件回调，
  不往内核写任何国家相关的规则或集合。所以内核里不存在 `frpfirewall_geo_*` 这类对象，
  `frpfirewall-panic.sh` 也不需要清理它们。

### 4.7 数据模型（SQLite）

```sql
-- 名单项（黑白名单共用表，用 kind 区分）
CREATE TABLE acl_entries (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         TEXT    NOT NULL,        -- 'white' | 'black'
  target       TEXT    NOT NULL,        -- IP 或 CIDR
  target_type  TEXT    NOT NULL,        -- 'ipv4' | 'ipv6' | 'cidr4' | 'cidr6'
  remark       TEXT,
  source       TEXT    NOT NULL DEFAULT 'manual',  -- manual | geoip | system
  country      TEXT,                    -- 冗余的属地，便于列表展示
  expires_at   DATETIME,                -- NULL = 永久
  created_at   DATETIME NOT NULL,
  updated_at   DATETIME NOT NULL,
  UNIQUE(kind, target)
);

-- 封禁记录
CREATE TABLE ban_records (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  target       TEXT    NOT NULL,
  target_type  TEXT    NOT NULL,
  reason       TEXT,
  source       TEXT    NOT NULL,        -- auto | manual | geoip
  trigger_user TEXT,                    -- 触发封禁的 frp user
  hit_count    INTEGER DEFAULT 1,       -- 阶梯次数
  country      TEXT,
  status       TEXT    NOT NULL,        -- active | expired | released
  banned_at    DATETIME NOT NULL,
  expires_at   DATETIME,
  released_at  DATETIME,
  released_by  TEXT
);
CREATE INDEX idx_ban_active ON ban_records(status, expires_at);

-- 策略（单行配置，或 key-value）
CREATE TABLE policies (
  id                     INTEGER PRIMARY KEY CHECK (id = 1),
  window_seconds         INTEGER NOT NULL DEFAULT 60,
  threshold              INTEGER NOT NULL DEFAULT 10,
  ban_durations          TEXT    NOT NULL DEFAULT '600,3600,86400,0', -- 秒，0=永久
  escalate_window_hours  INTEGER NOT NULL DEFAULT 24,
  ban_target_granularity TEXT    NOT NULL DEFAULT 'ip',   -- ip | cidr24
  fail_mode              TEXT    NOT NULL DEFAULT 'open', -- open | close
  auto_ban_enabled       INTEGER NOT NULL DEFAULT 1,
  geoip_block_enabled    INTEGER NOT NULL DEFAULT 0,
  geoip_block_countries  TEXT    NOT NULL DEFAULT '',     -- 逗号分隔 ISO 码
  geoip_mode             TEXT    NOT NULL DEFAULT 'blacklist' -- blacklist | whitelist
);

-- 事件审计
CREATE TABLE events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         DATETIME NOT NULL,
  category   TEXT NOT NULL,  -- login_attempt | login_blocked | user_conn | ban | unban | rule_change | config | geoip | auth
  ip         TEXT,
  country    TEXT,
  province   TEXT,
  user       TEXT,
  op         TEXT,
  detail     TEXT,
  actor      TEXT            -- 'system' | 'auto' | 用户名
);
CREATE INDEX idx_event_ts ON events(ts DESC);

-- 规则变更审计（回滚用）
CREATE TABLE rule_changes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         DATETIME NOT NULL,
  backend    TEXT NOT NULL,
  action     TEXT NOT NULL,     -- add_ban | del_ban | switch_mode | ...
  payload    TEXT NOT NULL,     -- JSON
  snapshot   TEXT,              -- 变更前快照（可选，用于回滚）
  result     TEXT NOT NULL      -- success | failed
);

-- 防火墙模式偏好与探测结果
CREATE TABLE firewall_profiles (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  preferred   TEXT NOT NULL,     -- 'auto' | 'iptables' | 'nftables'
  detected    TEXT,
  detected_at DATETIME,
  detail      TEXT               -- JSON：发行版、版本、冲突组件
);

-- 键值表：面板配置、凭据、密钥都在这里，不依赖任何外部配置文件
CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT,
  updated_at DATETIME NOT NULL
);
-- 键名约定：
--   cfg.*                 面板配置（监听地址、TLS、日志、frps 端口、可信回源段…）
--   admin_username        面板用户名
--   admin_password_hash   面板密码 bcrypt 哈希；为空表示尚未初始化
--   jwt_secret            面板 token 签名密钥，自动生成
--   setup_token           首次初始化令牌，设置完密码立即清空
-- 表名由 GORM 默认命名策略生成（复数下划线），上表名与库中实际一致。
```

### 4.9 配置存储

**没有配置文件。** 配置全部存在数据目录的 SQLite（`<data_dir>/frpfirewall.db`）里，
启动时只需要给出数据目录：

```bash
frpfirewall -data /var/lib/frpfirewall
```

启动流程：

1. `store.Open(dataDir)` 打开（必要时创建）数据库；
2. `AllSettings()` 一次读出全部键值 → `config.FromSettings()` 还原成配置对象，
   缺失或非法的项回落默认值（后续版本新增配置项无需写迁移脚本）；
3. 把当前版本有、而库里没有的键补写成默认值，**已存在的键一律不覆盖**；
4. `-listen` 参数只覆盖本次运行的面板监听地址，不落库（改错地址后用来救急）。

配置项按「运行期是否可变」分成两类：

| 类别 | 例子 | 生效方式 | 存放位置 |
|---|---|---|---|
| 启动期配置 | 监听地址、TLS 证书、日志级别、frps 端口、更新检查开关与来源 | 重启进程 | `settings` 表 `cfg.*` |
| 运行期策略 | 频次阈值、阶梯时长、国家封禁、速率限制、黑白名单 | 改完立即生效 | `policies` / `acl_entries` / `ban_records` / `events` 表 |
| 后端偏好 | iptables / nftables 切换 | 切完立即重建规则 | `firewall_profiles` 表 |

界面上改「启动期配置」后如实提示"需要重启"，不做假的热更新——监听地址与 TLS
在 `http.Server` 构造时就固定了，假装生效只会让人以为改动没保存。

更新检查的仓库名（`cfg.update.repo`）也归在启动期配置里：它决定 `update.Checker`
构造时绑定哪个仓库，运行期改不了。写入前会用 `netip` 之外的严格字符集校验
（只允许 `A-Za-z0-9-_.`，且必须是 `owner/name` 两段）——这个值会被拼进
`https://api.github.com/repos/{repo}/releases` 的 URL 路径，不校验就等于开了个
路径穿越的口子。

**首次初始化**：密码不再自动生成。启动时若 `admin_password_hash` 为空，
生成一次性令牌，打印到控制台并写入 `<data_dir>/setup_token.txt`（权限 0600）。
前端引导到初始化页，凭令牌设置用户名与密码，令牌随即从库和磁盘上清除。
这样即使面板直接开在公网，也不会出现"谁先访问谁就是管理员"。

### 4.8 API 清单

统一前缀 `/api/v1`。只有 `/auth/status`、`/auth/login`、`/auth/setup` 是公开接口，其余全部需要 JWT。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/auth/status` | **公开**，返回面板是否已初始化（前端据此决定跳初始化页还是登录页） |
| POST | `/auth/setup` | **公开**，首次初始化：凭一次性令牌设置用户名与密码，成功即返回 JWT |
| POST | `/auth/login` | **公开**，登录返回 JWT；未初始化时返回 403 |
| GET | `/auth/me` | 当前登录用户 |
| POST | `/auth/logout` | 登出 |
| POST | `/auth/password` | 修改密码 |
| GET | `/config` | 读当前持久化的配置（不含密钥），并指出是否与运行中的一致 |
| PUT | `/config` | 保存配置；如实返回 `restart_required` |
| GET | `/system/info` | 版本、运行时长、当前后端、依赖状态；含 `update` 字段但只回放缓存，不发网络请求 |
| GET | `/system/detect` | 重新探测环境（返回 §4.3 的探测结果） |
| POST | `/system/firewall/mode` | 切换 iptables/nftables |
| GET | `/system/update` | 读上一次的更新检查缓存（不联网）。未检查过时**不返回 `result` 字段**，避免前端拿空壳渲染 |
| POST | `/system/update/check` | 主动检查更新，真实联网查 GitHub。body 可选 `{"force":true}` 绕过服务端缓存 |
| GET | `/firewall/managed` | 本程序受管规则（结构化） |
| GET | `/firewall/system` | 系统完整规则（原始文本，只读） |
| GET | `/firewall/snapshot` | 当前后端的规则快照（纯文本） |
| POST | `/firewall/reconcile` | 手动触发一次同步 |
| POST | `/firewall/preview` | 预览将要下发的规则（dry-run，不落盘） |
| GET | `/acl/:kind` | 名单列表（kind=white/black），支持分页/筛选 |
| POST | `/acl/:kind` | 新增 |
| PUT | `/acl/:kind/:id` | 修改（备注/到期） |
| DELETE | `/acl/:kind/:id` | 删除 |
| POST | `/acl/:kind/batch` | 批量新增/删除 |
| GET | `/acl/:kind/export` | 导出（txt / json） |
| POST | `/acl/:kind/import` | 导入（去重、校验、预览后确认） |
| GET | `/bans` | 封禁列表（active/历史，含属地、来源） |
| GET | `/bans/active` | 活跃封禁（读内存，含剩余时间） |
| POST | `/bans` | 手动封禁 |
| DELETE | `/bans/:id` | 解封 |
| POST | `/bans/batch-delete` | 批量解封 |
| POST | `/bans/lookup` | 排障查询：某 IP 当前处于什么状态、命中几次 |
| GET | `/policy` | 读策略 |
| PUT | `/policy` | 改策略（立即生效） |
| POST | `/geoip/lookup` | 单 IP 查询（属地 + 当前拦截状态） |
| POST | `/geoip/lookup/batch` | 批量查询 |
| GET | `/geoip/status` | 三个库的加载状态、大小、更新时间 |
| POST | `/geoip/upload` | 上传 mmdb / xdb（校验文件头后原子替换） |
| GET | `/geoip/countries` | 可用国家列表（含中文名、ISO 码） |
| GET | `/events` | 事件流，**游标分页**（`limit` + `cursor`） |
| GET | `/events/stats` | 聚合统计（趋势、Top IP、Top 地区） |
| GET | `/events/changes` | 规则变更审计 |
| GET | `/frps/snippet` | 生成 frps.toml 需追加的配置片段 |
| GET | `/frps/health` | 插件自检（供 frps 配置前确认连通） |
| GET | `/frps/config` | 可选的 frps 加固配置片段 |
| POST | `/frps/handler` | **frps 插件入口**（非 JWT 鉴权，仅回环可访问） |

事件流用游标分页而不是 offset：事件表只增不减，深翻页时 offset 要先扫过并丢弃
前面所有行，代价随总量线性增长；游标（`id < before_id`）每页代价恒定。响应返回
`next_cursor` 与 `has_more`，前端用「加载更多」而不是页码。

---

## 5. 前端设计（Vue 3 + Element Plus）

技术栈：Vue 3 + Vite + TypeScript + Pinia + Vue Router + Element Plus + ECharts + Axios。

| 页面 | 关键内容 |
|---|---|
| 登录 Login | 单用户密码登录，失败 5 分钟窗口内 8 次即锁定 10 分钟 |
| 初始化 Setup | 首次访问引导页：凭启动时打印的一次性令牌设置用户名与密码 |
| 概览 Dashboard | 当前后端徽标、受管规则数、活跃封禁数、拦截趋势图（ECharts）、Top 攻击 IP、Top 来源国家、系统健康状态 |
| 防火墙配置 Firewall | 后端模式切换卡（含探测结果与冲突告警）、受管规则表、系统规则原文、「预览变更」抽屉、手动 reconcile |
| 黑白名单 ACL | 白 / 黑 Tab、搜索分页、新增/编辑对话框、批量导入（先 dry-run 校验去重再提交）、导出 |
| 封禁记录 Bans | 活跃封禁表（剩余时间实时倒计时）、历史表（状态筛选）、手动封禁、批量解封、排障查询 |
| 频控策略 Policy | 窗口秒数、阈值、阶梯时长编辑器（可增删/上移/永久档）、升级窗口、封禁粒度、fail-open/close、自动封禁与观察模式、地域封禁、连接速率限制 |
| IP 属地 GeoIP | 三个库的状态卡（加载状态/大小/更新时间）、上传替换、IP 查询工具（属地 + 当前拦截状态 + 窗口命中数），未加载库时给出降级提示 |
| frp 接入 Frps | 生成的 `frps.toml` 片段（一键复制）、插件连通性检测、受保护端口展示、可选加固项、判定链路说明 |
| 事件日志 Events | 事件日志（类别/时间范围/关键字筛选 + 游标分页）与规则变更审计双 Tab |
| 系统设置 Settings | 面板监听/TLS/账号、frps 对接、防护与日志、版本更新开关与来源；改启动期配置后如实提示需重启 |

通用能力（已实现）：
- 全局 toast 提示，所有写操作成功/失败明确反馈；401 自动跳登录。
- **策略页带脏标记**：改动后提示未保存，且「改了又改回去」能正确显示为未修改。
- 危险操作二次确认：解封、批量解封、删除条目。
- 顶栏徽标：后端模式、插件在线状态、活跃封禁数、库是否过期，任一异常高亮。
- **版本入口**：侧边栏底部的版本号可点击，打开版本对话框（当前版本、最新版本、
  更新说明、下载文件、发布页链接）。发现新版本时顶栏出现红标，
  并区分提示「正式版已发布，建议从预发布版切过去」。每个浏览器会话只自动查一次，
  服务端另有缓存，因此打开多少次面板都不会真的频繁打 GitHub。
- 前端产物通过 `go:embed` 打进二进制，路由用 hash 模式，未知路径回退到 `index.html`。

---

## 6. frps 需要增加的配置（前端生成）

程序生成的片段（前端展示 + 一键复制，**不自动改 frps 配置**）：

```toml
# ===== FrpFireWall 接入配置 =====
# 追加到 frps.toml 后执行 systemctl restart frps

[[httpPlugins]]
name = "frpfirewall"
addr = "127.0.0.1:9100"
path = "/frps/handler"
ops = ["Login", "NewUserConn"]
tlsVerify = false

# 不要把 "Ping" 加进 ops：心跳每客户端 30s 一次，挂上来会让插件调用量
# 乘以客户端数量，小内存机器上足以把 frps 拖垮。
```

要点说明（同步展示在前端）：
- `ops` 只填 `Login` 与 `NewUserConn`。**不要加 `Ping`**（心跳高频，会拖垮 frps，详见 D6）。
- `addr` 必须是 frpfirewall 监听地址；frpfirewall 默认只绑 `127.0.0.1`。
- 修改后需 `systemctl restart frps`，重启期间隧道断开（提示用户避开业务高峰）。
- 若 `Login` 走不通，frp 端会看到 `reject_reason` 里的封禁原因，便于排障。

可选增强（前端作为"进阶配置"展示）：

```toml
# 减少攻击面（可选）
transport.tls.force = true          # 只接受启用 TLS 的客户端
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
maxPortsPerClient = 10              # 限制单客户端代理数
```

---

## 7. 安全设计

### 7.1 防止把自己锁在门外（最高优先级）

| 措施 | 说明 |
|---|---|
| 系统保护名单（不可删除） | `127.0.0.0/8`、`::1`、本机所有网卡 IP、frps 所在机网段（可选） |
| SSH 来源自动加白 | 安装时读取 `$SSH_CLIENT` / `$SSH_CONNECTION`，把当前管理来源 IP 写入白名单 |
| CDN 回源段自动加白 | 内置 Cloudflare/EdgeOne/百度云加速回源段（见 D7） |
| 写入前 dry-run | `iptables-restore --test` / `nft -c`（见 D5） |
| 应用后回滚保护 | 健康检查（回环 + 管理端口 + frps bindPort）失败则自动回滚快照 |
| panic 救援脚本 | `frpfirewall-panic.sh`：只删归属本程序的对象 —— iptables 的 `FRPFIREWALL_GUARD` / `FRPFIREWALL_BLACK` 链、nftables 里带 `frpfirewall` 注释的规则与 `frpfirewall_*` 集合，支持 `--dry-run` |
| systemd 看门狗 | 程序异常退出时**不清规则**（保持封禁有效），下次启动 reconcile 收拢 |
| 独立链隔离 | 永不 flush 整表，绝不触碰非受管规则（见 D2） |

### 7.2 防误封

- 白名单优先级最高，命中即放行且永不封禁。
- 默认封禁粒度为单 `IP`；启用 `/24` 粒度时二次确认并提示影响范围。
- GeoIP 国家封禁默认**关闭**，启用时要求先在 UI 上预览"将影响 N 条 CIDR / M 个活跃 IP"。
- 自动封禁前有"观察模式"（只记录不封禁），便于上线初期验证阈值是否合适。

### 7.3 其它

- IP/CIDR 输入一律用 `netip.ParsePrefix` 严格校验后才拼进命令；所有外部命令走参数数组执行（不经 shell），杜绝命令注入。
- 首次启动生成一次性初始化令牌（落库 + 写 `setup_token.txt`），改密码/改用户名/清令牌在同一事务语义下完成，令牌比对用 `crypto/subtle.ConstantTimeCompare` 定长比较；设置成功后令牌与文件一并作废。
- 面板认证：bcrypt 密码 + JWT；默认只监听 `127.0.0.1:7930`，对外暴露需显式配置并支持 HTTPS（可配证书路径）。
- 密码哈希为空时登录接口直接返回 403，未初始化的面板不能被任何已有凭据登入。
- 登录面板本身也做速率限制，防止面板被爆破。
- 事件审计表记录所有管理操作（谁、何时、改了什么、结果）。
- frps 插件入口仅允许回环来源，其余一律 403。

---

## 8. 部署方式

单二进制 + SQLite 单文件，systemd 托管。完整单元文件在 `deploy/frpfirewall.service`。

```ini
[Unit]
Description=frpfirewall - frps 服务端插件防火墙
After=network-online.target
Wants=network-online.target

# 必须早于 frps 起来：frps 启动后立刻会开始回调插件，
# 插件没就绪时只能走 fail-open，那段窗口内等于没有防护。
Before=frps.service

[Service]
Type=simple
# 配置全部存在数据目录的 SQLite 里，启动只需要指定数据目录
ExecStart=/usr/local/bin/frpfirewall -data /var/lib/frpfirewall

Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=5

# 改防火墙只需要 NET_ADMIN；不要给 CAP_SYS_ADMIN 这类过度权限
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

# 用 full 而不是 strict：strict 会把 /run 也挂成只读，
# 而 iptables -w 需要写 /run/xtables.lock，开了会直接报错
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true

StateDirectory=frpfirewall

# 内存上限是必要的安全阀：本程序常驻且要解析 GeoIP，
# 一旦出现泄漏会拖垮整机（同机的 frps 也救不回来）
MemoryMax=512M
MemoryHigh=384M
LimitNOFILE=65535
```

- 数据目录：`/var/lib/frpfirewall/`（SQLite 库、GeoIP 库文件；初始化令牌在首次启动时生成，设置密码后作废）。
- 首次装完启动 → 日志打印一次性初始化令牌 → 浏览器打开面板，用令牌设置管理员密码。
- 端口：面板 `127.0.0.1:7930`（对外开放改 `0.0.0.0:7930` + 开 TLS）；
  插件 `127.0.0.1:9100`（必须回环）。
- **运行时依赖**：`iptables` 或 `nftables` 至少装一个（`auto` 优先 nftables）。
  **不需要 ipset**（见 D8）。
- 升级：跑 `install.sh update`，替换二进制 + `systemctl restart`，SQLite 自动 migration。
- **一键脚本** `scripts/install.sh` 一个文件管四件事（见 D10）：

  ```bash
  # 安装 / 升级 / 卸载 / 查状态
  curl -fsSL .../scripts/install.sh | sudo bash
  curl -fsSL .../scripts/install.sh | sudo bash -s -- update
  curl -fsSL .../scripts/install.sh | sudo bash -s -- uninstall [--purge]
  curl -fsSL .../scripts/install.sh | sudo bash -s -- status
  ```

  它会做环境检查、下载并逐个核对 sha256、原子替换二进制、注册服务，
  首次安装打印一次性初始化令牌。`uninstall` 会先停服务再清内核残留规则，
  数据目录默认保留；`-b <路径>` 是离线安装路径。
- 救援脚本 `scripts/frpfirewall-panic.sh`：把归属本程序的规则从内核里摘掉，
  只删自有链 / 集合 / 带 `frpfirewall` 注释的规则，不动系统原有规则。支持 `--dry-run`。
  安装后以 `frpfirewall-panic` 落在 `$PREFIX`，直接在 `$PATH` 里可用。

---

## 9. 开发计划（已完成）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P1 | 项目骨架、配置加载、SQLite migration、Gin 路由、API 认证 | ✅ 完成 |
| P2 | 防火墙驱动：探测 + iptables 驱动 + nftables 驱动 + 预览 | ✅ 完成 |
| P3 | 封禁引擎：滑窗计数、阶梯封禁、reconcile、保护名单 | ✅ 完成 |
| P4 | frps 插件服务 + 频控策略下发 | ✅ 完成 |
| P5 | GeoIP 双库 + 属地查询 + 国家封禁 | ✅ 完成 |
| P6 | 前端页面 + 登录 + 初始化页 + 系统设置 + 布局 | ✅ 完成 |
| P7 | 构建打包：go:embed、交叉编译、systemd、安装/救援脚本 | ✅ 完成 |
| P8 | 冒烟测试（177 项断言全通过） | ✅ 完成 |
| P9 | 版本号与自动发布：git 仓库 + `VERSION` + CI + tag 触发 Release + 前端检查更新 | ✅ 完成 |
| P10 | 发布闸门：版本号不高于已发布最高版本就不构建（`tools/versioncmp`） | ✅ 完成 |

**已做的验证**：真实起服务跑完整链路（177 项断言）—— 前端产物 embed 与 SPA 回退、
首次初始化令牌流程（错误令牌 401 / 过短密码 400 / 重复初始化 409 / 令牌文件清除）、
JWT 鉴权与防爆破、策略读写与非法输入拒绝、系统配置读写与落库（含回环校验、CIDR 校验、
`restart_required` 语义）、GeoIP 降级路径、黑白名单 CRUD 与批量导入去重、
手动封禁/解封与系统保护拒绝、frps 插件六种回调（含空 body 与未知 op 不 panic）、
事件游标分页与聚合统计、频次触发 → 阶梯封禁 → 解封、观察模式只记录不封禁、
版本与更新检查链路（`/system/info` 的 `version` / `version_full` / `is_prerelease`、
`/system/update` 未检查过时不返回空壳、`/system/update/check` 联网判定与最小间隔落入缓存、
更新检查配置读写后能原样还原、回填配置不会把其它开关清成零值）。
执行方式：`bash testdata/smoke.sh`（会自动还原被改动的策略与配置；版本断言取自 `VERSION` 文件而非硬编码）。

**发布链路实测**（真跑过，不是纸面推演）：

- CI 两个 job 全绿（前端 9/9、后端 11/11 步骤）。
- tag `v0.0.1-pre.01` 触发的 Release 工作流 15 个步骤全绿，产物为
  `frpfirewall-linux-amd64`（28.7 MB）、`frpfirewall-linux-arm64`（26.9 MB）、
  `sha256sums.txt`、`install.sh`、`frpfirewall.service`。
- release 属性正确：`prerelease=true`、`draft=false`、**不是 latest**
  （`/releases/latest` 返回 404）——正式版用户不会被引到这个预发布版上。
- 发布闸门用真实的 GitHub Releases 数据、配合 workflow 里逐字相同的命令验证：
  「已发布最高版本 = 本次 tag」时判定 `publish=false` 并跳过构建
  （没有 gh CLI / token，调不了 GitHub 的 re-run API，因此这条路径没能在
  真实 workflow 上触发过；真实 workflow 上跑到的是下面的自愈路径）。
- 意外条件下实测到一条自愈路径：release 被删后重推同一个 tag 能正常重建、
  15 个步骤全绿。这正是「基准取已发布 release 而非 git tag」带来的性质——
  顺便也证明**删 tag 会连带删掉它的 release**，别拿删 tag 当重跑手段。

**已做的单元测试**：`go test ./...` —— `internal/version` 覆盖版本号解析 / 格式化 / 比较 /
更新筛选（含正式版永不追预发布、预发布版同号正式版优先）；`internal/update` 覆盖正向缓存、
失败负缓存、强制绕过、`Peek` 不联网、非法 tag 计入 `skipped_tags` 而不整体失败；
`tools/versioncmp` 以 28 个子用例覆盖发布闸门的判定，含「预发布转正」
（`0.0.1 > 0.0.1-pre.99`）、「正式版已发布后推同号 pre 应跳过」、
「无法解析的历史 tag 不阻塞也不参与比较」，以及非法候选版本号必须硬报错。
另有一个测试把「`version.Version` 默认值必须等于 `VERSION` 文件内容」钉死——
两者脱节不会让任何构建失败（CI 与 Makefile 走的都是注入路径），
只会让裸 `go build` 出来的二进制自称一个错误的版本号。
另外用真实数据源端到端验证过：检查源指向 `cli/cli` 能取到最新正式版与其资产列表；
指向 `kubernetes/kubernetes` 时 7 个 `-alpha` / `-beta` / `-rc` tag 被跳过而不是导致整体失败。

**尚未在真机验证的部分**：iptables / nftables 的实际规则落盘。
Windows 上探测不到后端，驱动层只有编译与逻辑覆盖，需要到 Debian / Ubuntu 机器上
用 `iptables-save` / `nft -a list ruleset` 核对一次。
上线前建议先做一次「故意把管理端口封掉」的演练，确认 `frpfirewall-panic.sh` 能救回来。


---

## 10. 已确认的选型（来自需求澄清）

- 防火墙：**同时支持 iptables 与 nftables**（自动探测 + 手动切换），面向多种 Linux 发行版。
  后端不支持的能力（如 per-IP 限速）自动降级，只在 UI 上标注该项不可用，不阻断其它功能。
- 拦截落点：**双层** —— frps 插件拒绝 + 系统防火墙封 IP。
- GeoIP：**GeoLite2 + ip2region 双库**，运行期在应用层实时解析（见 D8）。
- 前端：**Vue 3 + Element Plus**。
- **不支持 Docker**：改防火墙需要 `CAP_NET_ADMIN` 且要操作宿主机 netns，容器化只会带来困惑。
- **不支持 CentOS**：只面向主流 Debian / Ubuntu 系。
- **保护范围**：只保护 frp 端口（`bind_port` + `proxy_ports`），不接管系统其它服务的规则。
- **连接速率限制**：对受保护端口做 per-IP 限速。nftables 用动态集合 + `limit rate over`，
  iptables 用 `hashlimit --hashlimit-mode srcip`；后端版本不够时该项自动置灰。
- **面板**：可对外网开放，单用户密码 + JWT，端口 **7930**。
- **不使用 ipset**：地区封禁在 IP 访问时解析（见 D8）。

---

## 11. 后续演进方向（非阻塞）

> 以下都是当前刻意不做的，记在这里避免以后重复讨论。

### 11.1 单机 vs 多节点

当前按 **单机** 设计：面板 + 引擎 + 插件在同一个进程，管一台 frps。
若将来需要「一个面板管 N 台 frps」，架构要改成 **中心面板 + 各节点 agent**
（面板下发策略、节点本地执行防火墙），工作量约增加 40%。

### 11.2 多用户与角色

当前是单用户 + JWT，没有 RBAC。真有需要时再加，现在加只会增加认证面的复杂度。

### 11.3 CDN 回源段

已内置 Cloudflare 回源段白名单（`internal/guard/protect.go`），
另外可在面板 **系统设置 → frps 对接 → 可信回源网段** 追加自定义回源 CIDR。
来自可信回源网段的访问按 `X-Forwarded-For` 判定真实客户端 IP（见 D7）。

### 11.4 与既有安全组件的关系

服务器上若装了 **宝塔 WAF** 或 ufw / firewalld，本程序不与它们争抢所有权：
只用自己的链 / 集合 / 带 comment 标记的规则，绝不 flush 整表（见 D2）。
宝塔如果会「清空自定义规则」，表现为本程序下发的规则被抹掉——
引擎的定时 reconcile 会自动补回，无需人工干预。
