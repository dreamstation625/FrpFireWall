# FrpFireWall

frps 服务端插件防火墙：频次限制 + 黑白名单 + IP 属地封禁，带一个内嵌的 Web 控制台。
产物是单个二进制，前端已 `go:embed` 打进去，部署时不需要任何运行时。

面向的场景是自建 frps 暴露在公网、日志里持续出现扫描和爆破。默认只保护 frp 端口，
不接管系统已有的防火墙规则。

## 文档

| 文档 | 内容 |
| --- | --- |
| 本篇 | 核心能力、快速开始、安装卸载、配置项、已知边界 |
| [`docs/FEATURES.md`](docs/FEATURES.md) | 功能详解：细分规则、地区拦截、封禁范围、出口 IP、拦截统计、GeoIP |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | 排障：面板打不开、忘记密码、判定顺序、误封救援 |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | 开发：构建、测试、代码结构 |
| [`docs/RELEASE.md`](docs/RELEASE.md) | 版本格式、CI 分级、发版流程与发布闸门 |
| [`docs/DESIGN.md`](docs/DESIGN.md) | 设计决策（D1…D30）与[关键设计约束完整版](docs/DESIGN.md#12-关键设计约束完整版readme-只摘了其中几条) |

## 能力

| 需求 | 做法 |
| --- | --- |
| 有人拿字典爆 token | 滑动窗口统计登录频次，超阈值自动封禁，阶梯升级（10 分钟 → 1 小时 → 1 天 → 永久） |
| 某地区 / 网段一直在试探 | 频控细分规则：按国家、省份、城市、IP 段、代理名、端口分流，命中的规则取代全局规则 |
| 某个端口被人反复扫 | 细分规则填目的端口，落点在**内核**，包在握手前就被丢掉 |
| 扫描器一波波来 | 手动 / 批量黑名单，支持 CIDR 整段；每条可选「全端口」「仅 frp 端口」「自定义端口」 |
| 某个地区一次都不许连 | 细分规则里的「直接拦截」：不等频次，命中就拒 |
| 想知道谁在访问隧道 / 谁加的封禁 | `NewUserConn` 回调逐条留痕；事件日志与规则变更审计两条线可查 |
| 封完才发现名单加错了 | 封禁带来源引用：删条目、停用规则时连带解禁，手动解封会反查背后那条并报条数 |
| 记录多了翻起来费劲 | 所有表格列宽可拖拽并记住；列表统一分页，可选每页 20 / 50 / 100 条，也能填页码跳转 |

拦截分两层：**应用层**在插件回调时拒绝这次连接并给出原因；**网络层**用 iptables / nftables
在握手之前丢包。

## 关键设计约束

改代码或判断行为前先看这几条（完整 12 条在 [`docs/DESIGN.md`](docs/DESIGN.md#12-关键设计约束完整版readme-只摘了其中几条)）：

1. **插件调用同步阻塞、必须 fail-open**：判定有 100ms 超时，超时或 panic 一律放行。
   宁可漏拦，也不能让插件挂掉把整条 frp 隧道拖断。
2. **绝不 flush 整表**：只用自己的链 / 集合 / 带 `frpfirewall` 注释的规则，
   ufw、firewalld、手工规则一律不碰。
3. **白名单是「豁免本程序封禁」，不是「全端口放行」**：实现是生成黑名单时把白名单减掉，
   不往内核写豁免规则。
4. **规则的落点由条件推出来，不是选的**：填了端口 → 内核（只能限速）；
   不填端口 → 应用层（能限速也能封禁）。「地区 / 代理」与「端口」不能同填，保存时直接报错。
5. **地区拦截是「命中即封该 IP」**：属地库只能"给 IP 问地区"，反查不出某国的 CIDR，
   所以地区条目一条内核规则都不预先写，而是等某个 IP 连上来查出属地才封它。
6. **封禁状态以数据库为准，重启靠全量重建受管链自愈**：进程退出时不清理内核规则
   （清理会让重启那几秒变成不设防的窗口），启动时筛一遍未到期的装回内存再重建。
   停机期间到期的会被清掉，不会留下"界面显示封禁中、内核其实没封"的行。

## 快速开始

### 1. 安装（Debian / Ubuntu）

```bash
curl -fsSL https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh | sudo bash
```

一条命令：校验环境（root / systemd / iptables 或 nftables）→ 下载并逐个核对 sha256 →
原子替换二进制 → 写 systemd 单元并启动。升级时新版本起不来会自动换回旧二进制。

- **先审再跑**（推荐）：`curl -fsSLO <脚本URL>` 下来 `less` 一遍再 `sudo bash install.sh`。
- **离线 / 指定版本**：二进制、`install.sh`、`frpfirewall.service` 放同一目录，
  `sudo ./install.sh -b ./frpfirewall-linux-amd64`；`-v 0.0.1-pre.01` 装指定版本。
  脚本默认只认正式版，要装预发布版加 `--pre`。
- **国内加速**：`... | sudo bash -s -- install --mirror https://<你的加速前缀>/`
  （脚本不内置任何第三方地址，用不用由你决定）。

### 2. 设置面板密码

面板默认监听 `0.0.0.0:7930`，装完对所有网卡可达。打开 `http://<本机IP>:7930` 会跳到初始化页，
填入启动时打印的令牌（同时保存在 `/var/lib/frpfirewall/setup_token.txt`）并自行设置密码，
令牌随即作废。

**令牌不能省**：面板默认对全网开放，去掉令牌就等于"谁先访问谁当管理员"——它要证明的是
你能读这台机器的日志或文件。

初始化完成后会**自动走一遍教学引导**（接通 → 定规则 → 查结果）；想再看，点顶栏
**「引导」**或右上角用户菜单里的「教学引导」。云服务器**记得放行安全组的 7930 入站**。

面板是管理接口，暴露面要主动想清楚：

- **开启 HTTPS**（系统设置 → HTTPS），否则登录密码是明文传输——这条别跳过
- 登录有防爆破：5 分钟窗口 8 次失败锁定 10 分钟
- 不想对外暴露就装的时候加 `--listen 127.0.0.1:7930`，再走 SSH 隧道
  `ssh -L 7930:127.0.0.1:7930 root@<服务器>`；或用云安全组只放行自己的出口 IP

### 3. 接入 frps

面板 → **frp 接入** → 复制配置片段（右上角可切 **TOML / JSON**，frp v0.52.0 起都支持）。

`frps.toml` 追加到文件末尾；`frps.json` 没有"追加"语法，要把 `httpPlugins` 元素
**合并进现有配置**（整个覆盖会丢掉 `bindPort` 等已有项）：

```toml
[[httpPlugins]]
name = "frpfirewall"
addr = "127.0.0.1:9100"
path = "/frps/handler"
ops = ["Login", "NewUserConn"]
tlsVerify = false
```

**`ops` 只填这两个，不要加 `Ping`** —— 心跳是每客户端 30s 一次，挂上来会让插件调用量
乘以客户端数，小内存机器上足以把 frps 拖垮。

同一页的「受保护端口」= `bindPort` ∪ 代理端口，决定「仅 frp 端口」封哪些端口。
`bindPort` 只读，能改的是代理端口那一半（支持区间，如 `20000-30000`），保存**立即生效**。

改完先验证再重启：

```bash
frps verify -c /etc/frp/frps.toml    # 或 frps.json
sudo systemctl restart frps
```

### 4. GeoIP 数据库（可选）

不放也能跑，只是属地显示与国家封禁不可用。三个库各自独立加载，缺哪个不影响其它库；
面板 **IP 属地** 页可一键下载更新（支持加速源）。各库作用与多库合并顺序见
[`docs/FEATURES.md`](docs/FEATURES.md#geoip-数据库可选)。

## 升级与卸载

```bash
SCRIPT=https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh

curl -fsSL $SCRIPT | sudo bash -s -- status       # 看当前版本与线上最新版
curl -fsSL $SCRIPT | sudo bash -s -- update       # 升级（未装则改用 install）
curl -fsSL $SCRIPT | sudo bash -s -- uninstall    # 卸载：清内核规则、删二进制与单元，数据目录保留
curl -fsSL $SCRIPT | sudo bash -s -- uninstall --purge   # 连数据目录一起删（二次确认）
```

常用开关：`-y` 免交互、`--force` 允许降级或同版本重装、`--no-start` 只装不启、
`--dry-run` 只解析不动手、`--pre` 允许预发布版。完整列表见 `--help`。
版本更新也可以在面板点侧边栏底部的版本号查看（只读检查，不自动替换自身）。

## 配置

没有配置文件。**所有配置都在数据目录的 SQLite（`data/frpfirewall.db`）里**，
在面板 **系统设置** 页修改。多数改动重启后生效；**代理端口**与**事件保留天数**立即生效。

启动只需指定数据目录：`frpfirewall -data /var/lib/frpfirewall`

| 项 | 默认值 | 说明 |
| --- | --- | --- |
| 面板监听 | `0.0.0.0:7930` | 默认对所有网卡开放；只给本机用 `127.0.0.1:7930` |
| HTTPS | 关闭 | 面板暴露公网时开启，否则密码明文传输 |
| 登录有效期 | 12 小时 | JWT token 的 TTL |
| 插件监听 | `127.0.0.1:9100` | 只允许回环，frps 必须同机 |
| bindPort | 7000 | frps 的 bindPort，用于下发连接速率限制 |
| 代理端口 | `80,443` | `NewUserConn` 参与判定的端口，支持区间（如 `20000-30000`） |
| 可信回源网段 | 空 | 来自这些 CIDR 的访问按 `X-Forwarded-For` 判定，避免封掉 CDN 节点 |
| 总开关 | 开 | 关闭后只判定不写规则 |
| 观察模式 | 关 | 只记录不封禁，上线前验证误伤 |
| 日志级别 | `info` | `debug` / `info` / `warn` / `error` |
| 事件保留 | 30 天 | 超期事件定时清理；填 `0` 永久保留。调小会立刻删除超期记录，不可恢复 |
| 在线检查更新 | 开 | 关闭后面板不访问 GitHub，纯内网部署建议关掉 |
| 检查来源 | `dreamstation625/FrpFireWall` | 查询 Release 的 GitHub 仓库（`owner/name`） |

运行期策略（频次阈值、阶梯时长、地域封禁、速率限制）在 **频控策略** 页，改完即时生效。

### 功能详解

具体口径、边界与踩坑点都在 [`docs/FEATURES.md`](docs/FEATURES.md)：

| 功能 | 一句话 |
| --- | --- |
| [频控细分规则](docs/FEATURES.md#频控细分规则) | 按国家 / 省份 / 城市 / 网段 / 代理名 / 端口分流，命中的取代全局规则 |
| [按地区拦截](docs/FEATURES.md#按地区拦截国家--省份--城市) | 名单条目选地区类型，命中即封该 IP（不预先占内核） |
| [黑名单封禁范围](docs/FEATURES.md#黑名单的封禁范围) | 每条可选「全端口」/「仅 frp 端口」/「自定义端口」 |
| [服务器出口 IP](docs/FEATURES.md#服务器出口-ip) | 探测本机公网出口并提示加白名单，避免自锁 |
| [防火墙拦截统计](docs/FEATURES.md#防火墙拦截统计) | 内核实际丢包统计（与事件日志是两套数字，别相加） |
| [事件日志](docs/FEATURES.md#事件日志记了什么) | 时间 / 类别 / IP / 属地 / 账号 / 代理 / 详情 / 操作者 |

## 运维

```bash
systemctl status frpfirewall
journalctl -u frpfirewall -f
systemctl restart frpfirewall
```

**误封导致连不上**（或规则下发后网络异常）：

```bash
sudo systemctl stop frpfirewall          # 必须先停，否则 reconcile 会把规则重新下发
sudo frpfirewall-panic                   # 只删归属 frpfirewall 的对象
sudo frpfirewall-panic --dry-run         # 先看会做什么
```

救援脚本只清网络层，应用层封禁记录还在数据库里。
**面板打不开、忘记密码、判定顺序** 见 [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)；
查某个地址为什么被拦：面板 **封禁记录 → 排障查询**，输入 IP 返回当前状态与命中原因。

## 已知边界

- **默认只保护 frp 端口**，不动 ssh、web 等其它服务的规则。黑名单选「全端口」或
  「自定义端口」是仅有的两处会波及 frp 以外端口的场景，需逐条显式开启。
- **自动封禁恒为全端口**：频次超限 / 地域命中的自动封禁不由人逐条确认，固定按 `all` 下发。
- **「自定义端口」只作用于内核层**：插件回调拿不到目的端口，所以它在插件侧与「全端口」
  等价（该地址照样被拒绝登录），只用来精确控制内核封哪几个端口。
- **手动黑名单不过滤 CDN 可信回源段**：自动封禁会跳过回源 IP，手工新增 / 导入的不检查 ——
  把 CDN 节点加进去会掐死一大片正常用户，选「仅 frp 端口」也不缓解（回源打的正是 frp 端口）。
- **地区拦截挡的是「已经露过面的人」**，不是一整个地区的所有地址；要提前封住一整段只能用 CIDR。
- **省份 / 城市条件只在 frp 协议流量上生效**（靠插件回调触发），纯 TCP 扫描不会命中，
  那部分由端口类规则（落内核）与连接速率限制兜底；且它们依赖属地库返回**中文名**，
  库里没中文名时不会命中。按国家封禁不受影响。
- **国家码与城市"写错不报错"**：国家码只校验两位字母、城市不校验真实性，写错的表现是
  **永远不命中**；省份查真实性，写错直接报错。配好建议先在 **IP 属地** 页核对写法。
- **只支持 Debian / Ubuntu 系**，不支持 CentOS / RHEL 与 Docker 部署（需 `CAP_NET_ADMIN`
  且要看到宿主机 netns）；**单用户**，一个面板账号 + JWT，没有 RBAC；**属地库需自行准备**
  （MaxMind 有许可限制，不便随包分发）。
- **防火墙规则的落盘与丢包计数解析都只验过输出样本，没在真实 Linux 上跑过**（开发机是
  Windows）。上线前用 `iptables-save` / `nft -a list ruleset` 核对，并演练一次救援脚本。
