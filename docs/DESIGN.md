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
| iptables | 三条自定义链：`FRPFIREWALL_GUARD`（主链）+ `FRPFIREWALL_BLACK`（全端口黑名单）+ `FRPFIREWALL_BLACK_FRP`（仅 frp 端口黑名单） |
| nftables | 集合 `frpfirewall_black` / `frpfirewall_black6` / `frpfirewall_black_frp` / `frpfirewall_black6_frp` / `frpfirewall_rate`；规则靠 `comment "frpfirewall:*"` 标记归属 |

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
                   ├─ -j FRPFIREWALL_BLACK         ← 全端口黑名单，跳转在前
                   ├─ -j FRPFIREWALL_BLACK_FRP     ← 仅 frp 端口黑名单（见 D14）
                   ├─ [限速规则]                   ← 可选
                   └─ -j RETURN
FRPFIREWALL_BLACK
                   └─ -s <黑名单> -j DROP          ← 逐条，无 dport 限定
FRPFIREWALL_BLACK_FRP
                   └─ -s <黑名单> -p tcp -m multiport --dports <frp 端口> -j DROP   ← 逐条
                      （UDP 同样一条，避免留下绕过路径）
```

黑名单单独放一个子链，是因为增量封禁/解封是高频操作：写在主链里每次都要算"插到第几条"、
还要处理删除后的序号漂移；放进子链后追加就是 `-A`、删除就是按内容 `-D`，完全不依赖位置。

按范围再拆一层子链（而不是在主链里给每条规则加条件），是为了让"改一条条目的范围"只动
一个子链的内容：`all` 与 `frp` 两条链各自独立增删，互不干扰，链上顺序也天然稳定 ——
不需要在改动时重新计算"这条该插在哪些规则前面"。

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

### D11. 面板默认监听 0.0.0.0，靠一次性令牌兜住"抢先初始化"

面板是管理接口，安全直觉上默认值该是 `127.0.0.1:7930`（只绑回环）。这里反着
来，默认 `0.0.0.0:7930`，代价和理由都记下来。

**为什么默认对外**：程序装在那台被防火墙保护的服务器上，而运维要从自己的机器
打开面板。默认只绑回环的后果是"装完打不开"，而改监听地址恰恰要进面板才能改——
绕不开的鸡生蛋。这个坑实际踩过：一键脚本打印的访问地址是 `http://<本机IP>:7930`，
服务却只绑回环，照着做必然连不上，很容易被误判成安装失败。

**代价**：面板从装好那一刻起就对全网可达，而且走明文 HTTP。

**用三道兜底**：
1. **一次性初始化令牌**（落库 + 写 `setup_token.txt`）——真正防"抢先初始化"的是
   这个。没有它，第一个扫到 7930 的人就能把自己设成管理员；有了它，只有能读到
   本机日志或文件的人（也就是机主）才设置得了密码。
2. **登录防爆破**：5 分钟窗口 8 次失败锁定 10 分钟。
3. **反复提示开 TLS**：安装完成时打黄字警告，README 单列一节讲安全要求。

**要收回来**：装的时候 `--listen 127.0.0.1:7930`。它写成 systemd 的 drop-in
（`frpfirewall.service.d/10-listen.conf`）而不是改主单元 —— 主单元是发布资产，
升级时整个被替换，写进去会丢；drop-in 在卸载时能干净删掉。

**监听地址有两个来源，优先级必须说清楚**：`--listen`（drop-in，启动参数）>
面板里的设置（数据库）。drop-in 里的 `-listen` 每次启动都生效，会盖住面板里的
值。所以安装完成提示、README、面板输入框提示三处都写明了"想用面板里的设置，
先删掉那个 drop-in"，重装时也不再把已有的 drop-in 静默删掉（见 D12）。

### D12. 默认值不进数据库；升级不删 drop-in

D11 把默认监听地址从 `127.0.0.1:7930` 改成了 `0.0.0.0:7930`，但老机器升级上来
仍然是回环地址。根因不在默认值，在**写库时机**，两个独立缺陷叠在一起：

**① 启动时把默认值补进数据库，等于把当时的默认值永久钉死。**

`run()` 原本会把所有缺失的配置项按 `cfg.ToSettings()` 补一行落库。它和
`FromSettings` 的语义是冲突的 —— 后者注释写着"缺失或非法的项回落到默认值，
这样后续版本新增配置项时不需要写迁移脚本"，也就是**缺失即默认**。一旦落库，
"缺失"就再也不成立了，此后任何版本改 `Default()` 都对老机器无效。

真实后果：`0.0.1-pre.02` 及更早的机器库里存着 `cfg.server.listen =
127.0.0.1:7930`，升到 `pre.03` 后读到的还是这行老值，`ss` 一看仍然只绑回环，
表现和"升级没生效"一模一样。

改成不写。默认值只活在二进制里，用户没碰过的项就一直是默认值，改默认值能
真正下达。用户在面板里点保存时 `handleUpdateConfig` 会把整份配置落库，此后
再改默认值不会动到它。

（残留：面板保存写的是**整份**配置，所以用户为了改别的设置点一次保存，也会顺手
把监听地址按当时的值钉进库。这时钉的是 `0.0.0.0`，是期望值，不算问题；真要彻底
消灭这类"顺带钉死"，得给每个键记"是不是用户显式改过"，为一个不痛的地方加一张
表不划算。）

代价：`settings` 表不再是一份"当前配置快照"，只看库里的行会缺项。可接受 ——
配置的真值本来就该由 `FromSettings(AllSettings())` 算出来，
`handleGetConfig` 正是这么做的，界面显示不会因此变化。
**不做**按"值等于旧默认值"自动迁移：分不清用户是"没改过"还是"故意只绑回环"，
猜错会把人从 SSH 隧道方案一脚踹成公网明文暴露。

**② 不带 `--listen` 重装时删掉 drop-in，删的可能是唯一一条进面板的路。**

原本的清理逻辑本意是"别让 `--listen` 装过一次就永远甩不掉"。但 ① 还没修的时候
这两件事会合成一个死结：库里是老回环地址 + drop-in 被删 → 服务退回只监听回环
→ 人进不去面板 → 也没别的地方能把监听改回来。升级反而把本来还能用的机器弄成
打不开。

改成：没给 `--listen` 就不动已有 drop-in，打一行提示说明它仍然生效、以及想让位
该删哪个文件。**卸载**时才收走。宁可留一个"有点粘"的覆盖文件（提示里给了命令），
也不要冒删掉救命通道的风险。

**③ 启动时对"只绑回环"给出显式警告。** 这是最容易把运维锁在门外的配置，日志里
一句话就能省掉去翻安全组、防火墙、代理的一圈。用 Warn 而不是 Info：默认值是
`0.0.0.0`，出现回环即意味着有人显式改过，值得唠叨一句（提示里注明"只有 SSH
隧道这一种访问方式的话忽略本行"）。

### D13. nftables 规则的落点按协议栈分开，不能只记一个

**触发过的真实故障**：某台机器上 `nft` 报

```
Error: conflicting protocols specified: ip vs. ip6
insert rule ip filter INPUT ip6 saddr @frpfirewall_black6 drop comment "frpfirewall:black6"
                              ^^^^^^^^^
```

根因是驱动里只存了一个落点（family/table/chain）。那台机器上存在的是
`table ip filter` + `chain INPUT`，于是整份脚本的每条规则都往 `ip` 家族里插 ——
包括那条 `ip6 saddr` 的。

nftables 的 family 决定这条链处理哪个协议栈：

| family | 处理 | 链里能写什么 |
|---|---|---|
| `inet` | IPv4 + IPv6 | `ip saddr` 与 `ip6 saddr` 都行 |
| `ip` | 只有 IPv4 | 写 `ip6` 表达式直接语法冲突 |
| `ip6` | 只有 IPv6 | 写 `ip` 表达式同理 |

而 `ip` 与 `ip6` 是彼此独立的家族，想同时管住两个协议栈就必须有**两条**链。
系统里 `table ip filter` 与 `table ip6 filter` 并存是常态（ufw、docker、
iptables-nft 生成的规则都长这样），所以驱动里存的是「每个协议栈一个落点」。

对比 iptables 驱动就能看出问题：它天然有 `fams []ipFamily`，`iptables` 与
`ip6tables` 各跑各的，不存在混淆的可能。nftables 侧把两个协议栈挤进一个
target 才埋下了这个雷。

**为什么这个错误特别隐蔽**：脚本有语法错误时 `nft -c -f -` 预检失败 → 按设计
**整份放弃**（这个设计是对的，绝不下发半截规则）→ 结果是那条链上一个规则都没有，
**IPv4 封禁跟着一起失效**。而界面上只看到一句"规则语法预检失败"，看不出是
IPv6 那条规则把 IPv4 的一起陪葬了。

配套的三条：

- **缺一半必须告警。** 只找到 `ip` 没有 `ip6`（或反过来）时，缺的那一半确实下发
  不了。机器若有那半边连通性，被封的地址换个协议栈就能绕过 —— 而这从界面上
  完全看不出来，所以必须由后端明确说出来。
- **只生成能落地的规则。** 限速表达式里的 `saddr` 是 IPv4 的（动态集合元素类型为
  `ipv4_addr`），所以只落在 v4 链上；IPv6 要另建一个 `ipv6_addr` 的动态集合，
  暂未实现。宁可这一半跳过，也不为对称塞一条会让整份事务被拒的规则。
- **`AddBlock` / `DelBlock` 找不到该协议栈的落点时报错，不静默成功。** 静默成功
  会让用户以为已经封上了。

**验证方式**：把「生成脚本」抽成纯函数 `renderScript`，
`internal/firewall/nftables_test.go` 直接断言脚本文本。这类错误桩命令永远测不出来
（桩不解析语法、只会点头），真实内核上又只有报错那一刻才知道 —— 只有断言脚本
本身能防住。`Preview` 复用同一个函数，保证"预览到的"就是"会下发的"（原来是两份
独立实现，迟早漂移）。

### D14. 黑名单的封禁范围按条目选，默认全端口

**需求**：黑名单原来只有一种行为 —— 该地址到本机的**全部端口**一律 DROP。实际使用中
分成两类需求：一类是确认的纯攻击源，想彻底断开；另一类只想挡掉它对 frp 的访问，
本机其它服务（尤其是同一来源还需要访问的）不该被牵累。

**决策：范围做成每条条目一个字段（`all` | `frp`），默认 `all`。**

- **为什么是每条而不是全局开关。** 一个全局开关表达不了"A 只扫 frp、B 是纯攻击源"
  这种必然共存的局面。更要紧的是，切全局开关会**一次性改写所有现有条目的含义** ——
  用户改一条新条目的意图，变成了动到另外几十条的既有行为。
- **为什么默认 `all`。** 升级上来的存量条目必须保持原来的行为，否则升级本身就成了
  一次静默的防护降级。同理，**自动封禁固定 `all`**：它不是人逐条确认过的决定，
  放宽到只封 frp 端口等于给暴力破解者留一条继续扫其它端口的路；需要放宽的场景
  走人工改条目范围。

**内核落点**：两种范围落在不同的链 / 集合里，互不干扰。

| 后端 | 全端口 | 仅 frp 端口 |
|---|---|---|
| iptables | `FRPFIREWALL_BLACK` | `FRPFIREWALL_BLACK_FRP` |
| nftables | 集合 `frpfirewall_black` / `black6` | 集合 `frpfirewall_black_frp` / `black6_frp` |

链上的顺序必须是**全端口在前、仅 frp 端口在后**：`frp` 范围是全端口的子集，全端口
命中就 `DROP` 掉了，后面的规则永远不会被读到，多出来的只是一次比较。反过来放则
全端口规则要等 frp 规则先走一遍。

这里有个 nft 特有的坑：`insert rule` **一律插到链首**，所以脚本里的书写先后与链上的
实际顺序**相反**。想让链上是「全端口 → 仅 frp 端口」，脚本文本就得**倒着输出**。
`internal/firewall/nftables_test.go` 的 `insertOrder` 辅助函数专门还原这个语义，
否则测试会以相反的期望通过。

**范围对插件层是空操作。** 插件回调（`Login` / `NewUserConn`）本来就只作用于 frp 连接，
`all` 与 `frp` 对它完全等价。所以插件的判定代码不需要知道范围存在 —— 这也是为什么
范围只影响内核侧而不影响"能不能登录"。

**兜底方向必须偏严。** `toBlockTargets` / `restoreBans` / `BanView` / 前端渲染，
凡是读到空值或非法值的地方一律回落 `all`。回落 `frp` 等于把一条"封全端口"的条目
悄悄放松成"只封 frp 端口"，是安全语义上的降级；宁可显示得严一点。

**同址归并。** 同一个地址可能同时来自手动黑名单与自动封禁，两处范围还可能不同。
`desired()` 用 map 归并而不是拼接：全端口已经覆盖 frp 端口，同址再写一条 frp 规则
纯属冗余，还会变成"为什么这里有两行"这种需要解释的问题。**冲突时严格范围胜出。**

**frp 端口集合 = `bindPort` + `proxyPorts`**，且 **TCP 与 UDP 都要封**：`bindPort` 是 TCP，
但代理端口里可能有 UDP 服务，只封 TCP 会留下一条 UDP 绕过路径。iptables 的 `multiport`
单条规则最多 15 个**端口或区间**，超了要分片（区间写法见 D15 —— 数的是区间个数，
不是区间里含多少个端口）。

**更新语义：不带 scope 不能改范围。** 更新接口的 `scope` 用指针类型区分"没传"和
"传了空串" —— 只改备注的请求不带该字段，若按普通字符串绑定就会得到 `""`、归一化成
`all`，等于顺手把一条 `frp` 条目放宽成封全端口。改个备注不该有这种副作用。

**导入格式向后兼容。** 第二列只有恰好是 `all` / `frp` 时才被当作范围，否则整体按备注
处理，所以老版本导出的两列文件（`地址,备注`）能直接导入。代价是备注恰好写成这两个词
时会被误认，属于刻意接受的取舍 —— 导出文件常被留档或拿去别的机器用，
格式不兼容就是实打实的数据损失。

**已知缺口：手动黑名单不过滤 CDN 可信回源段。** `desired()` 只剔除系统保护地址与
白名单地址，不看 `TrustedProxies`。自动封禁会因为它是可信回源而放过，但**手工加进去的
CDN 节点 IP 会照封不误** —— 封掉一个边缘节点就是掐死一大片正常用户。选 `frp` 范围
并不缓解这个问题（回源打的正是 frp 端口）。这一条当前靠界面提示与人工判断兜住，
未做程序化拦截。

**测试**：`iptables_test.go`（规则生成、顺序、端口归一化、预览与下发一致）、
`nftables_test.go`（双栈、集合 flush、链上顺序还原）、`handlers_acl_test.go`
（范围归一化、导入格式与导出回读闭环）。


### D15. 端口用区间表达，不展开成单个端口

**问题**：`proxy_ports` 原本是 `[]int`。但 frps 的 `allowPorts` 最常见的写法就是一整个
大区间，实测用户机器上就是 `20000-30000`。逐个列举的代价：

| | 展开成单端口 | 区间表达 |
|---|---|---|
| 用户要填的 | 10001 个数字 | `20000-30000` |
| iptables 规则条数 | 10001 ÷ 15 ≈ **667 条** × 2 协议 | **1 条** × 2 协议 |
| nft 集合元素 | **10001 个** | **1 个** |

**决策：新增 `internal/portrange` 包，端口统一用「区间集合」表达（`Set []Range`）。**

- **为什么单独一个包而不是塞进 `config` 或 `firewall`。** 两边都要用它，谁当宿主都会让
  另一边的依赖方向变别扭。解析、归一化、渲染是纯函数，独立出来也最好测。
- **归一化由类型自己兜住。** `Parse` / `Ports` / `Merge` 出来的 `Set` 一定已合并、去重、
  排序。上一版的教训是把"归一的义务"留在函数签名之外，调用方带着重复端口进来，生成出
  读起来像写错的规则。驱动入口再调一次 `Normalize()` 兜底（有人直接手写 `Set` 字面量）。
- **相邻区间也算重叠，要合并。** `80,81` 并成 `80-81` 后匹配集合完全一致，但
  multiport 少占一个名额、nft 集合少一个元素。有间隔的不合并 —— 那等于顺手多封了
  中间的端口。
- **非法写法必须报错，不能静默丢弃。** 早先的 `csvToInts` 会悄悄跳过越界值；
  用户以为配了、实际下发不出来，这种"以为保护了其实没保护"最难发现。
  前端也做一份同样的校验，是为了给出能看懂的错误，而不是让用户对着一句
  "请求格式不正确"猜自己哪里写错了。
- **两种后端的区间写法不同，必须分开渲染。** iptables 认 `--dports 20000:30000`，
  nft 认 `dport { 20000-30000 }`。实测交叉使用会直接报错（`invalid port/service
  '20000-30000'`），所以 `iptPorts` / `nftPorts` 各包一层，调用点不碰分隔符。
- **multiport 的 15 个名额数的是「区间个数」**，不是一个区间里含多少端口。
  所以切块按区间个数切，10001 个端口依然是 1 个名额。
- **限速规则拆块后共用同一个 `--hashlimit-name`。** 各块各算一份配额会让实际放行量
  随块数翻倍。

**持久化与接口形态**：`Set` 在 JSON 里就是文本（`"80,443,20000-30000"`），
和设置页那个输入框一一对应，中间不做结构转换。同时也接受 `[80,443]` 和裸数字，
让老客户端与手写请求体不至于直接报错。

**真机验证**（Debian 12 / nftables 1.0.6 / iptables 1.8.9）：

```
tcp dport { 7020, 20000-30000 } ip saddr @frpfirewall_black_frp drop comment "frpfirewall:black-frp"
udp dport { 7020, 20000-30000 } ip saddr @frpfirewall_black_frp drop comment "frpfirewall:black-frp"
```

两条规则覆盖 10001 个端口，且 `bind_port`（7020）与区间正确合并成一个表达式。
`tools/remote-range-test.js` 是可重放的验证脚本，`tools/assert-selftest.js`
用真实抓到的内核输出离线自检断言本身。

**测试**：`portrange_test.go`（解析容错、合并、切块、JSON 往返、越界夹取）、
`config/settings_test.go`（落库格式往返、老值兼容、坏值回落方向）、
`firewall` 侧的区间渲染与"宽区间不膨胀"断言。


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
│   ├── portrange/         # 端口区间集合：解析 / 合并 / 切块 / 按后端渲染（含单元测试）
│   ├── firewall/
│   │   ├── driver.go      # Driver 接口 + 受管对象名常量
│   │   ├── detect.go      # 系统与后端探测
│   │   ├── iptables.go    # 三条自定义链实现（全端口 / 仅 frp 端口黑名单分链）
│   │   ├── iptables_test.go
│   │   ├── nftables.go    # 集合 + 插系统 input 链的实现
│   │   └── nftables_test.go   # 直接断言生成的 nft 脚本（桩命令测不出语法问题）
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
│   │   ├── handlers_acl_test.go    # 范围归一化 + 导入格式与导出回读闭环
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
iptables -w -N FRPFIREWALL_BLACK 2>/dev/null || true       # 全端口黑名单
iptables -w -N FRPFIREWALL_BLACK_FRP 2>/dev/null || true   # 仅 frp 端口黑名单
iptables -w -C INPUT -j FRPFIREWALL_GUARD 2>/dev/null || iptables -w -I INPUT 1 -j FRPFIREWALL_GUARD

# 主链只负责分流，不承载具体 IP；全端口的跳转排在仅 frp 端口之前
iptables -w -A FRPFIREWALL_GUARD -j FRPFIREWALL_BLACK
iptables -w -A FRPFIREWALL_GUARD -j FRPFIREWALL_BLACK_FRP
iptables -w -A FRPFIREWALL_GUARD -j RETURN          # 限速规则存在时插在两者之间

# 封禁 / 解封：纯追加 + 按内容删除，不用关心位置
iptables -w -A FRPFIREWALL_BLACK -s 1.2.3.4 -j DROP
iptables -w -D FRPFIREWALL_BLACK -s 1.2.3.4 -j DROP

# 只封 frp 端口：TCP 与 UDP 各一条（proxyPorts 里可能有 UDP 服务，
# 只封 TCP 会留下一条绕过路径）；区间写成 lo:hi，超过 15 个区间时按 multiport 上限分片
iptables -w -A FRPFIREWALL_BLACK_FRP -s 1.2.3.4 -p tcp -m multiport --dports 7000,80,443,20000:30000 -j DROP
iptables -w -A FRPFIREWALL_BLACK_FRP -s 1.2.3.4 -p udp -m multiport --dports 7000,80,443,20000:30000 -j DROP
```

要点：
- **不引入 ipset。** 封禁条数由封禁记录数约束，属于可接受范围；真要上千条时优先引导用户切到 nftables 后端。
- **按范围分链，而不是在主链里给每条规则加 dport 条件**（见 D14）：两条链各自独立增删，
  改一条条目的范围不会牵动另一条链的内容，也就不需要计算"这条该插在哪些规则前面"。
- 白名单不落内核（见 D3），所以链里没有白名单相关规则。
- IPv6 走 `ip6tables`，链名与结构完全相同。
- 若系统用的是 `iptables-nft`（nft 后端），照样可用，但注意与 nftables 驱动**不要同时启用**，UI 上互斥。

#### nftables 驱动的具体落地

集合建在自己的名字空间里，规则插进系统已有的 input 链。family/table/chain 由
探测决定，两种典型形态：

```bash
# 形态一：系统有 inet/filter/input —— 一条链同时承载双栈
nft -f - <<'EOF'
add set inet filter frpfirewall_black     { type ipv4_addr; flags interval; }
add set inet filter frpfirewall_black_frp { type ipv4_addr; flags interval; }
add set inet filter frpfirewall_black6     { type ipv6_addr; flags interval; }
add set inet filter frpfirewall_black6_frp { type ipv6_addr; flags interval; }
add set inet filter frpfirewall_rate      { type ipv4_addr; flags interval; }

# 注意：这几行的书写顺序与链上顺序是**相反**的 —— insert 一律插到链首，
# 所以想让链上是「全端口 → 仅 frp 端口」，脚本就得倒着输出（见 D14）。
# 下面按"脚本实际生成的顺序"列出，v6 与 udp 的对应行省略。
insert rule inet filter input tcp dport { 7020, 20000-30000 } ip saddr @frpfirewall_black_frp  drop comment "frpfirewall:black-frp"
insert rule inet filter input ip  saddr @frpfirewall_black      drop comment "frpfirewall:black"
insert rule inet filter input ip6 saddr @frpfirewall_black6     drop comment "frpfirewall:black6"
EOF
```

执行完上面这个事务后，链上的实际顺序（链首 → 链尾）是：

```
全端口(v4) → 全端口(v6) → 仅 frp 端口 tcp(v4) → tcp(v6) → udp(v4) → udp(v6) → 限速 → 原有规则…
```

```bash
# 形态二：系统是 table ip filter + table ip6 filter（ufw / docker /
# iptables-nft 常见）—— 两个家族互不相通，必须各插各的链
nft -f - <<'EOF'
add set ip  filter frpfirewall_black     { type ipv4_addr; flags interval; }
add set ip  filter frpfirewall_black_frp { type ipv4_addr; flags interval; }
add set ip6 filter frpfirewall_black6     { type ipv6_addr; flags interval; }
add set ip6 filter frpfirewall_black6_frp { type ipv6_addr; flags interval; }
add set ip  filter frpfirewall_rate      { type ipv4_addr; flags interval; }

insert rule ip  filter INPUT ip  saddr @frpfirewall_black      drop comment "frpfirewall:black"
insert rule ip6 filter INPUT ip6 saddr @frpfirewall_black6     drop comment "frpfirewall:black6"
# 仅 frp 端口的规则同样按各自家族插进各自的链，dport 表达式相同
EOF
```

这个形态正是 D13 那个故障的场景：`ip` 家族的表里**不能**出现 `ip6 saddr` 表达式，
写错一条会让整份脚本预检失败，连 IPv4 的封禁一起失效。

要点：
- **不建自己的 base chain**，只往系统已有链里插规则（原因见 D3）。
- **落点按协议栈分开记**（见 D13）：驱动存的是「每个协议栈一个落点」，不是单个
  family/table/chain。往 `ip` 家族的链里写 `ip6` 表达式，nft 会拒绝整份脚本。
- 所有变更通过 `nft -f` 一次性提交，天然原子；提交前先用 `nft -c -f -` 做语法预检。
- 限速用集合 + `limit rate over N/second burst M packets`，需 nft ≥ 0.9.3。
  动态集合元素类型是 `ipv4_addr`，所以限速只落在 IPv4 链上。
- 规则归属靠 `comment` 标记识别；读回来时用 `nft -a list chain` 拿 handle，
  用 `nft -j list ruleset` 做集合探测（一次调用拿全部 INPUT 链，按家族分组）。

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
- **插件层不看封禁范围**（见 D14）：回调本来就只作用于 frp 连接，条目上的 `all` 与 `frp`
  对这里的判定结果完全等价。范围只影响内核侧下发什么规则，不影响"能不能登录"。
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
  scope        TEXT    NOT NULL DEFAULT 'all',  -- 'all' | 'frp'，只对黑名单有意义（见 D14）
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
  scope        TEXT    NOT NULL DEFAULT 'all',  -- 'all' | 'frp'（见 D14）
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
| PUT | `/acl/:kind/:id` | 修改（备注/到期/范围；范围不传即保持原值，见 D14） |
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
| 黑白名单 ACL | 白 / 黑 Tab、搜索分页、新增/编辑对话框、批量导入（先 dry-run 校验去重再提交）、导出。黑名单多一列「范围」（全端口 / 仅 frp 端口），白名单不显示该列（见 D14） |
| 封禁记录 Bans | 活跃封禁表（剩余时间实时倒计时）、历史表（状态筛选）、手动封禁（可选封禁范围）、批量解封、排障查询 |
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
- 面板认证：bcrypt 密码 + JWT；默认监听 `0.0.0.0:7930`（理由见 D11），支持 HTTPS（可配证书路径）。
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
- 端口：面板 `0.0.0.0:7930`（默认对所有网卡开放，要收回来用 `--listen` 或面板
  里的设置；对外可达时务必开 TLS）；
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
