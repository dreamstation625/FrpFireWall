# FrpFireWall

frps 服务端插件防火墙：频次限制 + 黑白名单 + IP 属地封禁，带一个内嵌的 Web 控制台。
产物是单个二进制，前端已通过 `go:embed` 打进去，部署时不需要任何运行时。

面向的场景是自建 frps 暴露在公网、日志里持续出现扫描和爆破。默认只保护 frp 端口，
不接管系统已有的防火墙规则；黑名单条目可以逐条选「全端口」，这是唯一会波及 frp 以外端口的场景。

---

## 能力

| 需求 | 做法 |
| --- | --- |
| 有人拿字典爆 frpc 的 token | 滑动窗口统计登录尝试频次，超阈值自动封禁，阶梯升级（10 分钟 → 1 小时 → 1 天 → 永久） |
| 港澳台、某省、某个网段来的一直在试探 | 频控细分规则：按国家/地区、中国省份、IP 段、被访问端口分流，命中的规则取代全局规则 |
| 某个端口被人反复扫 | 细分规则里填目的端口，落点在**内核**，包在握手之前就被丢掉 |
| 扫描器一波波来 | 手动 / 批量黑名单，支持 CIDR 整段；每条可选「全端口」「仅 frp 端口」或「自定义端口」 |
| 直接切掉某些地区 | GeoIP 双库属地解析，国家黑名单（拒绝某些地区）或白名单（只放行某些地区） |
| 想知道谁在访问隧道 | `NewUserConn` 回调带访问者 IP，逐条留痕 |
| 不知道某条封禁是谁加的 | 事件日志与规则变更审计两条线，全部可查 |

拦截分两层：应用层在插件回调时直接拒绝这次连接并给出原因；网络层用 iptables / nftables
在握手之前就把包丢掉。

---

## 关键设计约束

这几条是踩坑之后定下来的，改代码前先读：

1. **`ops` 不要挂 `Ping`。** frps 心跳是每客户端 30 秒一次，挂上 `Ping` 会让插件调用量
   乘以客户端数，连接一多就把 frps 拖死。默认只挂 `Login` + `NewUserConn`。

2. **插件调用是同步阻塞的，必须 fail-open。** 判定有 100ms 超时，超时或 panic 一律放行。
   宁可漏拦，也不能因为插件挂了让整条 frp 隧道全断。

3. **绝不 flush 整表。** iptables 侧只用自己的三条链（`FRPFIREWALL_GUARD` 主链、
   `FRPFIREWALL_BLACK` 全端口黑名单、`FRPFIREWALL_BLACK_FRP` 端口限定黑名单），
   nftables 侧只有 `frpfirewall_*` 集合和带 `comment "frpfirewall"` 标记的规则。
   ufw / firewalld / 手工规则一律不碰。

4. **nftables 不建自己的 hook 链。** 同一 hook 上多个 base chain 按 priority 依次执行，
   一条 `policy accept` 的链放在后面会把后续链的判决吃掉。所以规则是插入到系统已有 input
   链的最前面，不匹配就自然往下走。

5. **规则落点按协议栈分开。** nftables 的 `ip` 与 `ip6` 是互不相通的两个家族，所以 v4 与
   v6 的规则各自落在能承载它的那条链上（`inet` 家族一条链同时管两者）。往 `ip` 家族的链里
   写 `ip6` 表达式，nft 会判定语法冲突并拒绝**整份**脚本 —— 连 IPv4 的规则一起失效。
   系统里只有单一协议栈的 INPUT 链时，缺的那一半会给出告警，因为被封的地址换个协议栈
   就能绕过。

6. **白名单是「豁免本程序封禁」，不是「全端口放行」。** 实现方式是在生成黑名单时把白名单
   地址减掉，不往内核写豁免规则。

7. **属地解析只在 IP 访问时实时进行**，不下沉成 ipset 之类的内核集合。库文件常驻内存，
   查询是纯内存操作。

8. **黑名单可以只封 frp 端口。** 每条黑名单条目带一个范围：`all`（该地址到本机的全部端口
   一律丢弃）或 `frp`（只丢弃 frp 服务端口，即 bindPort + 代理端口）。默认 `all`。
   只封 frp 端口时对方仍能访问本机其它服务，所以它挡的是「用 frp 打进来的人」而不是
   「这个人本身」；要彻底断开就选 `all`。两种范围在内核上落在不同的链 / 集合里，
   改动其中一种不会影响另一种的现有规则。

9. **频控细分规则的落点不是用户选的，是推出来的，而且「地区 + 端口」不能写在同一条里。**
   要按*被访问的端口*分流只能在内核做（frps 插件回调拿不到目的端口），
   要按*来源属地*分流只能在应用层做（属地库只能"给 IP 问地区"，反查不出某个国家的 CIDR 列表）。
   两条合起来：填了端口就落内核、只能限速；不填端口就落应用层、能限速也能封禁。
   同时写两边**直接报错**，不会保存下来静默地少生效一半。
   详见 `docs/DESIGN.md` 的 D16。

---

## 快速开始

### 1. 构建

需要 Go 1.26+ 和 Node 20+。

```bash
make release    # 交叉编译 linux/amd64 与 linux/arm64，产物在 dist/
make build      # 只构建当前平台
```

### 2. 安装（Debian / Ubuntu）

一条命令，自动下载对应架构的二进制、校验 sha256、装 systemd 单元并启动：

```bash
curl -fsSL https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh | sudo bash
```

装完会打印初始化令牌。脚本只认正式版；要装预发布版加 `--pre`，要装指定版本加 `-v 0.0.1-pre.01`。

**先审脚本再执行**（推荐，脚本可以直读）：

```bash
curl -fsSLO https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh
less install.sh
sudo bash install.sh
```

**离线安装**：把二进制、`install.sh`、`frpfirewall.service` 放到同一目录，指定二进制路径：

```bash
sudo ./install.sh -b ./frpfirewall-linux-amd64
```

国内服务器直连 GitHub 慢的话，加加速前缀（脚本不内置任何第三方地址，用不用由你决定）：

```bash
curl -fsSL .../install.sh | sudo bash -s -- install --mirror https://<你的加速前缀>/
```

脚本做的事：校验环境（root / systemd / iptables 或 nftables）→ 下载并逐个核对 sha256 →
原子替换二进制 → 写 systemd 单元并启动。升级时如果新版本起不来，会自动换回旧二进制，
不会把防护留在半残状态。

### 3. 设置面板密码

面板默认监听 `0.0.0.0:7930`，装完对所有网卡可达，直接打开 `http://<本机IP>:7930`
就会跳到初始化页。填入启动时打印的令牌（同时保存在
`/var/lib/frpfirewall/setup_token.txt`）并自行设置密码，令牌随即作废。

**令牌不能省**：面板默认就是对全网开放的，去掉令牌就等于"谁先访问谁当管理员"。
它要证明的是你能读到这台机器的日志或文件，也就是证明你是机主。

用云服务器的话，**记得放行安全组 / 防火墙的 7930 入站**——监听开了但安全组没
放行，照样连不上。

**不想对外暴露**，装的时候就把监听收回来：

```bash
curl -fsSL .../install.sh | sudo bash -s -- --listen 127.0.0.1:7930
```

然后走 SSH 隧道访问，密码不会以明文过公网：

```bash
ssh -L 7930:127.0.0.1:7930 root@<服务器>
# 本地浏览器打开 http://127.0.0.1:7930
```

面板本身走的是 HTTP。**只要它对公网可达，登录密码就是明文传输的**，所以对外
暴露时请务必在面板里开启 TLS（系统设置 → HTTPS）。

### 4. 接入 frps

面板 → **frp 接入** → 复制配置片段。卡片右上角可切换 **TOML / JSON**：frp 从 v0.52.0 起
两种格式都支持，用哪一份取决于你手上那个配置文件的后缀。

用 `/etc/frp/frps.toml` 的话，把这段追加到文件末尾：

```toml
[[httpPlugins]]
name = "frpfirewall"
addr = "127.0.0.1:9100"
path = "/frps/handler"
ops = ["Login", "NewUserConn"]
tlsVerify = false
```

用 `frps.json` 的话，JSON 没有「追加一段」这种语法，要把 `httpPlugins` 元素合并进现有
配置里（**别拿它整个覆盖文件**，那会丢掉 `bindPort` 等已有项）：

```json
{
  "httpPlugins": [
    {
      "name": "frpfirewall",
      "addr": "127.0.0.1:9100",
      "path": "/frps/handler",
      "ops": ["Login", "NewUserConn"],
      "tlsVerify": false
    }
  ]
}
```

`ops` 只填这两个。**不要加 `Ping`** —— 心跳是每客户端 30s 一次，挂上来会让插件调用量
乘以客户端数，小内存机器上足以把 frps 拖垮。

同一页的「受保护端口」可以直接改：**受保护端口 = `bindPort` ∪ 代理端口**，它决定
「仅 frp 端口」的封禁范围与全局限速兜底规则的落点。`bindPort` 只读（它属于 frps 自己的
配置），能改的是代理端口那一半 —— 填你 `allowPorts` 里那组端口（支持区间，例如
`20000-30000`），点保存**立即生效，不需要重启**。不改也没关系：只影响「仅 frp 端口」
范围封哪些端口，与接入本身无关。

改完先验证再重启，不用等重启失败才发现写错：

```bash
frps verify -c /etc/frp/frps.toml    # 或 frps.json
sudo systemctl restart frps
```

面板上的连通性检测可以直接验证插件链路是否通。

### 5. GeoIP 数据库（可选）

不放也能跑，只是属地显示与国家封禁不可用。三个库各自独立加载，缺哪个都不影响
其它库可用：

| 文件 | 面板下载源 | 作用 |
| --- | --- | --- |
| `GeoLite2-Country.mmdb` | `P3TERX/GeoLite.mmdb` 的 release | 国家封禁的基础，做地域拦截必须有 |
| `GeoLite2-City.mmdb` | 同上 | 省 / 市（约 64MB；**不含运营商**） |
| `ip2region.xdb` | `lionsoul2014/ip2region` 的 `ip2region_v4.xdb` | 国内属地细化，不依赖 MaxMind 账号；运营商只有它能给 |

#### 一键下载更新

面板 **IP 属地** 页每个库下面都有「下载更新」按钮，直接从上面的源拉最新版，
不用手动下载再上传。按钮旁边标着**预估大小**（如「约 64MB」，点下去之前对耗时有个数），
以及一个「前往下载源仓库」链接 —— 想先去看看上游更新了什么、或手动取文件都方便。
几个要点：

- **走加速源**。这些都托管在 GitHub 上，国内直连基本不可达，所以下载支持选择公共
  加速源（ghfast.top / gh-proxy.com / ghproxy.net / gh.llkk.cc），默认是「自动选择」——
  依次尝试、直连排在最后兜底，某个源挂了会自动换下一个。
- 下载完**先校验文件头再替换**，校验不过旧库原样在用。把一个下到一半的坏文件换上去，
  属地功能会整个失效，比安装失败严重得多。
- 同一时刻只允许一个下载任务（两个下载会撞在同一个临时文件上）。已经在下的时候再点
  会直接提示，而不是排队等一个 64MB 的文件。
- 加速源是公共代理，随时可能挂。列表由后端内置并实测维护，**不接受自定义前缀**：
  让调用方随便传一段前缀等于开放任意 URL 转发，面板能连到的内网地址会被逐个探测。
- 全部源都失败时，错误里会列出每个源各自的原因。只回一句「下载失败」没法指导下一步。

也可以自己把文件放进数据目录（自动加载），或者在面板 **IP 属地** 页上传本地文件 ——
上传路径与下载走同一套「写临时文件 → 校验文件头 → 原子替换 → 热加载」。

#### 同时装了多个库时的合并顺序

- **国家 / 大洲以 MaxMind 为准**：Country 库优先，Country 库没查到时由 City 库补。
- **省 / 市 / 运营商以 ip2region 为准**：它会覆盖 MaxMind 给出的省和市。
- **只装 ip2region 时**，国家字段按 xdb 记录里的 **ISO 国家码**判断（中国是 `CN`）。
  不能按「有没有省市」判断 —— 国外记录同样带省市，1.1.1.1 在 xdb 里是
  `Australia|Queensland|Brisbane|0|AU`，按「有省市就算中国」会把它标成 `CN`，
  「只放行中国」的白名单就形同虚设，而且界面上显示的国家名还是「中国」，看不出异常。

---

## 配置

没有配置文件。**所有配置都存在数据目录的 SQLite（`data/frpfirewall.db`）里**，
在面板 **系统设置** 页修改，改动重启服务后生效。

启动只需要指定数据目录：

```bash
frpfirewall -data /var/lib/frpfirewall
```

| 项 | 默认值 | 说明 |
| --- | --- | --- |
| 面板监听 | `0.0.0.0:7930` | 默认对所有网卡开放；只给本机用 `127.0.0.1:7930` |
| HTTPS | 关闭 | 面板暴露公网时开启，否则密码是明文传输 |
| 登录有效期 | 12 小时 | JWT token 的 TTL |
| 插件监听 | `127.0.0.1:9100` | 只允许回环，frps 必须同机 |
| bindPort | 7000 | frps 的 bindPort，用于下发连接速率限制 |
| 代理端口 | `80,443` | `NewUserConn` 回调参与判定的端口，支持区间写法（如 `20000-30000`） |
| 可信回源网段 | 空 | 来自这些 CIDR 的访问按 `X-Forwarded-For` 判定，避免封掉 CDN 节点 |
| 总开关 | 开 | 关闭后只判定不写规则 |
| 观察模式 | 关 | 只记录不封禁，上线前验证误伤 |
| 日志级别 | `info` | `debug` / `info` / `warn` / `error` |
| 在线检查更新 | 开 | 关闭后面板不访问 GitHub，纯内网部署建议关掉 |
| 检查来源 | `dreamstation625/FrpFireWall` | 查询 Release 的 GitHub 仓库（`owner/name`） |

运行期策略（频次阈值、阶梯时长、地域封禁、速率限制）在 **频控策略** 页，改完即时生效，不用重启。

### 频控细分规则

**频控策略** 页分两张卡：上面是**细分规则**（可有多条、按顺序匹配），下面是**全局规则**（兜底）。

匹配顺序是从上到下，**第一条命中的规则取代全局规则** —— 窗口、阈值、阶梯、限速全部换成
那条规则的。一条都没命中才走全局规则。地域封禁名单不受影响，它始终先生效。

一条规则的条件可以是（同一维度内多选是「或」，不同维度之间是「且」）：

| 条件 | 写法 | 落点 |
| --- | --- | --- |
| 国家 / 地区 | 下拉多选 ISO 码 | 应用层 |
| 省份 | 下拉多选（中国省级行政区） | 应用层 |
| 来源 IP / 网段 | `1.2.3.4, 203.0.113.0/24` | 看有没有填端口 |
| 目的端口 | `443, 20000-30000` | **内核** |

**落点决定了这条规则能做什么：**

- **应用层**（不填端口）：由 frps 插件在每次登录时判定，可以限速也可以封禁。
  限速按来源 IP 独立计数。
- **内核**（填了端口）：由系统防火墙按目的端口丢包。**内核只能丢包，不能封禁** ——
  超限的包根本到不了 frps，应用层无从知道它超限。所以填了端口之后封禁配置会变成不可用。

**「地区」和「端口」不能出现在同一条规则里**，保存时会直接报错。原因是地区只有 frps 插件
能判（它拿不到被访问的端口），端口只有内核能判。想同时限两个维度，请拆成两条规则 ——
两条规则按顺序匹配，先命中的生效，所以「某地区访问某端口」这种组合要用网段 + 端口来表达。

省份取值已经做了归一化：界面里给的是「广东」，属地库返回「广东省」也照样命中。
所以从 **IP 属地** 页复制过来的省份名可以直接粘进规则里。属地查不到时按不命中处理
（不会因为查不到就变成"命中所有人"）。

规则改动和全局策略一起保存（后端在同一次事务里落盘）。规则表上方如果出现红框，
说明有规则编译不过 —— 那种规则**不会生效**，红框里会给出具体原因。

### 黑名单的封禁范围

黑名单每条条目单独设置封禁范围，在 **黑白名单 → 黑名单** 页的「范围」列可以看到，
新增 / 编辑时选择，批量导入时可指定该批的默认范围：

| 范围 | 实际效果 | 什么时候用 |
| --- | --- | --- |
| `all`（默认） | 该地址访问**本机全部端口**的入站包一律丢弃，含 SSH、面板 | 确认是纯攻击源，不怕误伤；或被扫得受不了想彻底断掉 |
| `frp` | 只丢弃 frp 服务端口（bindPort + 代理端口，TCP 与 UDP 都包含）上的入站 | 只想挡掉对方对 frp 的访问，还要让本机其它服务保持可达 |

`frp` 范围涉及的端口集合 = **bindPort + 代理端口**。代理端口在 **系统设置** 页填写，
支持区间写法，直接照抄 frps 的 `allowPorts` 即可：

```
80,443                        # 逐个列举
20000-30000                   # 整个区间，落库就是这一行，不会展开成 10001 条规则
80,443,20000-30000,7000-7100  # 混着写，逗号 / 分号 / 空格分隔都认
```

区间是**原样下发**给内核的（iptables 写 `--dports 20000:30000`，nft 写 `dport { 20000-30000 }`），
所以封一个大区间和封一个端口，规则条数一样。改动代理端口后需要在 **系统设置** 页保存并
重启服务才生效。

选择 `all` 之前请确认这个地址不会同时是你的运维入口 —— 全端口封禁会把 SSH 一起挡掉，
届时只能用 `scripts/frpfirewall-panic.sh` 或带外控制台来救。

导入文件里第二列只有恰好是 `all` / `frp` 时才被当作范围，否则整体按备注处理，
所以老版本导出的两列文件（`地址,备注`）可以直接导入：

```
1.2.3.4,frp,扫描源        # 只封 frp 端口，备注"扫描源"
1.2.3.0/24,办公网          # 范围取该批默认值，备注"办公网"
1.2.3.5                   # 范围取该批默认值
```

**白名单没有范围**（恒为 `all`）：它描述的是「豁免谁的封禁」，本身不产生封禁动作，
所以界面上不显示这一列，接口传了也会被忽略。

### 面板打不开怎么排查

先看服务到底绑在哪个地址，这一步就能把"监听问题"和"网络/安全组问题"分开：

```bash
ss -lntp | grep 7930
```

- 显示 `0.0.0.0:7930` → 监听没问题，去查云安全组 / 本机防火墙 / 代理
- 显示 `127.0.0.1:7930` → 只绑了回环，别的机器连不上，按下面处理

改监听地址有两个地方，优先级不同，别搞混：

- **安装时的 `--listen`** 写成 systemd 启动参数覆盖
  `/etc/systemd/system/frpfirewall.service.d/10-listen.conf`
- **面板里改**（系统设置 → 监听地址）写进数据库，改完重启生效

`-listen` 一旦给了就盖住数据库里的值。所以先看有没有覆盖文件：

```bash
systemctl cat frpfirewall | grep ExecStart
```

#### ⚠️ 从 0.0.1-pre.02 及更早升上来的，监听地址不会自动变

那些版本的默认值就是 `127.0.0.1:7930`，而且首次启动时会把它写进数据库。升级只
换二进制，库里那行老地址原样留着，**新版本的默认值对老机器完全无效**。

改回来（任选一种）：

```bash
# 办法一（推荐）：让脚本写，文件名和权限都不会搞错
curl -fsSL https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh \
  | sudo bash -s -- update --pre --listen 0.0.0.0:7930

# 办法二：手写覆盖文件
sudo mkdir -p /etc/systemd/system/frpfirewall.service.d
sudo tee /etc/systemd/system/frpfirewall.service.d/10-listen.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/frpfirewall -data /var/lib/frpfirewall -listen 0.0.0.0:7930
EOF
sudo systemctl daemon-reload && sudo systemctl restart frpfirewall

# 办法三：进了面板之后，在「系统设置 → 监听地址」改成 0.0.0.0:7930 保存并
#         重启，值就落进数据库了；之后上面的覆盖文件可以删掉
```

`ExecStart=` 那行空行不能省：systemd 里 `ExecStart` 是**追加**语义，不清空会变成
两条启动命令抢同一个端口，服务起不来。

文件名也必须正好是 `10-listen.conf`。systemd 会加载 `service.d/` 下**所有**
`.conf`，里面只要还有第二份带 `ExecStart` 的（手抄时少写个数字前缀就会这样），
一样是两条命令抢端口，而且报错只有 `start request repeated too quickly`，很难
往覆盖文件上联想。装的时候如果看到「… 里也有 ExecStart」的告警就是这个原因：

```bash
ls -l /etc/systemd/system/frpfirewall.service.d/
```

想只让本机访问（走 SSH 隧道 `ssh -L 7930:127.0.0.1:7930 root@<服务器>`）就用
`--listen 127.0.0.1:7930`。但注意：面板只绑回环时，服务启动日志里会有一条 WARN
提醒你别的机器连不上——那是有意为之的话可以忽略。

改错地址把自己关在门外时，可以用启动参数临时救急（不写库、只影响本次运行）：
`frpfirewall -data /var/lib/frpfirewall -listen 0.0.0.0:7930`。

重新安装时**不会**自动删除已有的覆盖文件——它可能是你唯一能进面板的通道。要让它
让位就手动删，安装提示里会把命令打出来。

### 面板的安全要求

面板是管理接口，默认监听 `0.0.0.0:7930`（对所有网卡开放），还管着防火墙规则和
frps 插件，所以暴露面要主动想清楚：

- **开启 HTTPS**，否则登录密码是明文传输——这条别跳过
- 登录有防爆破：5 分钟窗口 8 次失败锁定 10 分钟
- 初始化令牌用完即废，不会留下固定口令
- 不想对外暴露就用 `--listen 127.0.0.1:7930` 配 SSH 隧道，或者用云安全组
  只放行你自己的出口 IP

---

## 运维

### 升级与卸载

同一个脚本管三件事：`install` / `update` / `uninstall`（缺省是 `install`）。

```bash
SCRIPT=https://raw.githubusercontent.com/dreamstation625/FrpFireWall/main/scripts/install.sh

# 看当前版本与线上最新版
curl -fsSL $SCRIPT | sudo bash -s -- status

# 升级（未装则改用 install）
curl -fsSL $SCRIPT | sudo bash -s -- update

# 卸载：停服务、清内核规则、删二进制与 systemd 单元，数据目录保留
curl -fsSL $SCRIPT | sudo bash -s -- uninstall

# 连数据目录一起删（有二次确认与多重路径护栏）
curl -fsSL $SCRIPT | sudo bash -s -- uninstall --purge
```

已经装到本机的话，`frpfirewall-panic` 也在 `$PATH` 里，不用再去找脚本文件。

常用开关：`-y` 免交互、`--force` 允许降级或同版本重装、`--no-start` 只装不启、
`--dry-run` 只解析版本和地址不动手、`--pre` 允许预发布版。完整列表见 `--help`。

### 出事了怎么救

误封导致连不上，或规则下发后网络异常：

```bash
sudo frpfirewall-panic              # 清掉所有受管规则
sudo frpfirewall-panic --dry-run    # 先看会做什么
```

它只删归属 frpfirewall 的对象（两条自有链 + 带 `frpfirewall` 注释的规则 + `frpfirewall_*` 集合），
不动系统原有规则。**进程还在跑的话会在下次 reconcile 时把规则重新下发，
所以要先 `systemctl stop frpfirewall`。**

救援脚本只清网络层，应用层的封禁记录还在数据库里。

### 常用命令

```bash
systemctl status frpfirewall
journalctl -u frpfirewall -f
systemctl restart frpfirewall
```

### 忘记面板密码

把数据库 `settings` 表里的 `admin_password_hash` 置空后重启，会重新进入初始化流程：

```bash
sqlite3 /var/lib/frpfirewall/frpfirewall.db \
  "update settings set value='' where key='admin_password_hash';"
systemctl restart frpfirewall
```

### 排障

面板 **封禁记录 → 排障查询**：输入一个 IP，返回它当前的状态
（白名单 / 黑名单 / 已封禁 / 可信回源 / 系统保护）、窗口内命中次数与命中原因。

---

## 版本与发布

### 版本号格式

只有两种形态：

| 形态 | 含义 |
| --- | --- |
| `0.0.1` | 正式版 |
| `0.0.1-pre.01` | 预发布版，序号从 `01` 起，固定两位 |

同一号段内**正式版大于预发布版**：`0.0.1 > 0.0.1-pre.99`。

### 检查更新

面板侧边栏底部的版本号可以点击，打开版本信息对话框。发现新版本时顶栏会出现红标。

两条轨道互不跨越：

- **正式版只提示正式版更新**，永远不会把正式版用户引到 `-pre` 版本上；
- 预发布版用户能同时看到更高序号的预发布版和正式版，
  且当同号正式版发布时会优先被推过去（`0.0.1-pre.03` → `0.0.1`）。

检查走 GitHub Releases API，只读不下载——**本程序不会自动替换自身**，
新版本需要你自己下载并重装（自更新涉及替换运行中的可执行文件与回滚，风险不划算）。

服务端对结果有一小时缓存，失败结果缓存十分钟，所以离线环境不会因为频繁重试拖慢面板。
服务器访问不了 `github.com` 时会在对话框里如实报错，也可以在 **系统设置** 里直接关掉。

### CI 分级

`push` 到 `main` 不会每次都跑一遍完整构建，按变更范围分档：

| 档 | 触发条件 | 跑什么 |
| --- | --- | --- |
| 日常 | 任何提交 | `go vet` + 单元测试 |
| 前端 | 动过 `web/` | 上面这些 + 前端构建 |
| 发版 | `VERSION` 有变化 | 上面这些 + 安装脚本测试、版本脚本测试、`go build` |

分档的理由：`go vet` 与单元测试几十秒就出结果，挡的正是**编译器看不见**的那类问题
—— 改过 JSON tag 而按字符串 key 取值的引用点没跟着改就是一例（`"from"` 编译得过、
`go vet` 也过，只有跑测试才炸）。这类错等发版当天才发现，代价太大。而 `npm ci`
与交叉编译只在真要出包时才有意义。

改动范围由 `.github/workflows/ci.yml` 的 `changes` job 用 `git diff` 算出来，
各 job 再按它决定跑不跑。拿不到比较基准时（首次推送、强制推送、手动触发）一律按
「都变了」处理：多跑一遍只是慢几十秒，漏跑则会让没人构建过的提交悄悄进 `main`。

### 发版流程

版本号散落在四处，`VERSION` 只是其中一个 —— 另外三处是
`internal/version/version.go` 里的默认值、`web/package.json`、
`web/package-lock.json`（后者两处）。只改 `VERSION` 不会编译失败，
但 `internal/version` 有一条对账用例要求默认值与 `VERSION` 一致，
漏改会让单元测试挂掉；如果此时 tag 已经推上去，Release 会在同一步失败，
且失败前不产出任何资产。

所以用脚本一次改完，别手改：

```bash
# 1. 四处一起改
bash scripts/version-bump.sh 0.0.1-pre.07
# 2. 提交
git add -A && git commit -m "chore: 版本升至 0.0.1-pre.07"
# 3. 推 main
git push origin main
# 4. 等 main 的 CI 跑绿 —— 这一步不能省，见下
# 5. 打同名 tag 推上去（v 前缀必需）
git tag v0.0.1-pre.07 && git push origin v0.0.1-pre.07
```

第 4 步的意义：Release 工作流本身就带 `go vet` 与单元测试，CI 挂过的提交
推 tag 也一定会在相同的位置失败。区别是失败一次会白打一个 tag，还得把 tag
删掉重打 —— 等 CI 只是几十秒的事。

这一步改动了 `VERSION`，所以跑的是**全量**（前端构建、脚本测试、交叉编译都跑）；
日常提交那档只跑 `go vet` 与单元测试。也就是说第 4 步等到的结果，
和 Release 工作流会看到的是同一套。

CI（`.github/workflows/release.yml`）会自动：校验 tag 与 `VERSION` 一致 →
过发布闸门 → 跑 `go vet` 与单元测试 → 构建前端 → 交叉编译 `linux/amd64` 与 `linux/arm64` →
实地跑一遍二进制确认版本号注入成功 → 生成 `sha256sums.txt` → 创建 Release。

tag 里带 `-pre.` 的会被自动标记为 **Pre-release**，不会成为 latest；
正式版则标记为 latest。发布物包含两个架构的二进制、校验和、`install.sh` 与 systemd 单元。

`VERSION` 的格式也由 CI 看门：写 `0.1.0-dev` 这类会被直接拒绝。
`scripts/version-bump.sh` 用的是同一套正则，非法格式在本地就被挡住。

### 发布闸门

**只有版本号真的提升了才会构建。** 工作流在动手构建之前，先拿候选 tag 的版本号与
已发布的 release 比对，必须**严格高于**其中最高的那个，否则打印一条 notice 后
跳过整个构建与发布（工作流本身仍算成功）。

会被挡下的情形：

| 场景 | 结果 |
| --- | --- |
| 重复推送同一个 tag | 跳过，而不是报「release 已存在」 |
| 推一个比线上更旧的版本 | 跳过，避免把 latest 指回旧版本 |
| 正式版已发布，再推同号 `-pre` | 跳过（`0.0.1-pre.02 < 0.0.1`，属倒退） |
| 发布失败后重跑同一个 tag | **正常发布** |

最后一行是关键：比较基准取的是**已发布的 release**，不是 git tag。tag 在 release
建成之前就已存在，若拿 tag 当基准，「构建失败」或「release 创建失败」之后重跑会被
判成「没有提升」而永远跳过，失败的发布就再也修不好了。

比较逻辑直接复用 `internal/version`（也就是面板里检查更新用的同一套），
免得在 CI 里另写一份产生漂移——尤其「同号段正式版大于预发布版」这条规则很容易写反。
守门程序在 `tools/versioncmp`，有独立单元测试。

---

## 开发

```bash
make version  # 显示将要编译进二进制的版本号（读 VERSION 文件）
make web      # 构建前端到 internal/web/dist
make build    # 构建当前平台二进制
make test     # 单元测试 + go vet + go build
make smoke    # 对已启动的实例跑接口冒烟测试
```

单元测试覆盖版本号解析/比较/更新筛选（`internal/version`）与更新检查的缓存、
轨道规则、失败降级（`internal/update`）：

```bash
go test ./...
```

一键脚本有自己的回归测试。它会起一个**假 GitHub Releases 服务**，用桩命令替换
`systemctl` / `iptables` / `install` / `uname` / `id`，在临时目录里真的跑一遍
安装 → 升级 → 回滚 → 卸载，并把脚本里的版本比较逻辑与 Go 侧逐条对照：

```bash
bash testdata/test-install.sh
```

全程不碰真实的 `/usr/local/bin`、`/etc/systemd/system` 与本机防火墙，不需要 root。

本地起服务：

```bash
go build -o testdata/frpfirewall.exe ./cmd/frpfirewall
./testdata/frpfirewall.exe -data testdata/data
```

前端开发模式（API 代理到 7930）：

```bash
cd web && npm run dev
```

### 代码结构

```
VERSION               版本号唯一来源，CI 会校验 tag 与它一致
cmd/frpfirewall/      入口，命令行参数与装配
internal/version/     版本号注入、解析、比较与更新筛选规则
internal/update/      GitHub Releases 更新检查（带缓存，只读）
internal/config/      配置模型与 SQLite 持久化
internal/model/       数据模型（ACL / 封禁 / 策略 / 频控细分规则 / 事件）
internal/store/       GORM + 纯 Go SQLite 数据层
internal/firewall/    后端抽象与 iptables / nftables 驱动
internal/geoip/       双库属地解析（mmdb + xdb）
internal/guard/       判定引擎：滑窗计数、细分规则匹配、封禁、reconcile
internal/frpsplugin/  frps httpPlugins 协议实现
internal/api/         REST API 与 JWT 鉴权
internal/web/         go:embed 前端产物
web/                  Vue 3 + Vite + Element Plus 前端
tools/versioncmp/     发布闸门：判断版本号是否高于已发布的最高版本
.github/workflows/    CI 与 tag 触发的自动发布
deploy/               systemd 单元
scripts/
  install.sh          一键脚本：在线安装 / 升级 / 卸载
  frpfirewall-panic.sh 紧急清理受管防火墙规则
testdata/
  smoke.sh            接口冒烟测试（对着已启动的实例跑）
  test-install.sh     一键脚本回归测试（假 Release 服务 + 桩命令，全离线）
  fake-release-server.py
docs/DESIGN.md        设计方案
```

---

## 已知边界

- **默认只保护 frp 端口**，不动 ssh、web 等其它服务的规则。黑名单条目可选「全端口」
  或「自定义端口」范围，这是仅有的两处会影响到 frp 以外端口的场景，需要逐条显式开启。
- **自动封禁恒为全端口。** 频次超限 / 地域命中的自动封禁不由人逐条确认，固定按 `all`
  下发；想放宽到只封 frp 端口或某几个端口，只能改成人工处理。
- **「自定义端口」只作用于内核层。** 插件回调拿不到被访问的目的端口，所以自定义范围
  在插件侧的判定与「全端口」等价（该地址一样会被拒绝登录）；它只用来精确控制内核
  封哪几个端口。这是有意的取舍：宁可插件侧封严一点，也不出现"名单显示封着、
  frp 却能连"。
- **手动加的黑名单不过滤 CDN 可信回源段。** 自动封禁会跳过可信回源 IP，但手工新增 /
  导入的黑名单条目不做这个检查 —— 把 CDN 节点 IP 加进去会掐死一大片正常用户，
  选「仅 frp 端口」也不缓解（回源打的正是 frp 端口）。加之前请先核对。
- **不支持 CentOS / RHEL。** 目标是 Debian / Ubuntu 系；其它发行版理论上能编译，
  但 nftables 版本差异可能影响 per-IP 限速能力。
- **不支持 Docker 部署。** 改防火墙需要 `CAP_NET_ADMIN` 且要看到宿主机 netns。
- **单用户**，一个面板账号 + JWT，没有 RBAC。
- **属地库需自行准备**，MaxMind 有许可限制，不便随包分发。
- **细化到省份 / 国家的细分规则只在 frp 协议流量上生效。** 落点在应用层的规则靠 frps 插件
  回调触发，所以纯 TCP 扫描（不发起 frp 登录）不会命中它 —— 那部分由端口类规则
  （落内核）和连接速率限制兜底。
- **省份条件依赖属地库返回中文省份名。** 库文件里没有中文名时（例如只装了
  GeoLite2-Country，或 ip2region 未加载），省份字段会是英文或空，这类规则不会命中；
  按国家封禁不受影响。
- **防火墙规则的实际落盘未在真实 Linux 上验证过**（开发机是 Windows），
  上线前请用 `iptables-save` / `nft -a list ruleset` 核对，并演练一次救援脚本。
