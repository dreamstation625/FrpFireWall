# FrpFireWall

frps 服务端插件防火墙：频次限制 + 黑白名单 + IP 属地封禁，带一个内嵌的 Web 控制台。
产物是单个二进制，前端已通过 `go:embed` 打进去，部署时不需要任何运行时。

面向的场景是自建 frps 暴露在公网、日志里持续出现扫描和爆破。它只保护 frp 端口，
不接管系统已有的防火墙规则。

---

## 能力

| 需求 | 做法 |
| --- | --- |
| 有人拿字典爆 frpc 的 token | 滑动窗口统计登录尝试频次，超阈值自动封禁，阶梯升级（10 分钟 → 1 小时 → 1 天 → 永久） |
| 扫描器一波波来 | 手动 / 批量黑名单，支持 CIDR 整段 |
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

3. **绝不 flush 整表。** iptables 侧只用自己的两条链（`FRPFIREWALL_GUARD` / `FRPFIREWALL_BLACK`），
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

面板 → **frp 接入** → 复制配置片段，追加到 `/etc/frp/frps.toml`：

```toml
[[httpPlugins]]
name = "frpfirewall"
addr = "127.0.0.1:9100"
path = "/frps/handler"
ops = ["Login", "NewUserConn"]
tlsVerify = false
```

```bash
sudo systemctl restart frps
```

面板上的连通性检测可以直接验证插件链路是否通。

### 5. GeoIP 数据库（可选）

不放也能跑，只是属地显示与国家封禁不可用。把文件放到数据目录即可自动加载：

| 文件 | 来源 | 作用 |
| --- | --- | --- |
| `GeoLite2-Country.mmdb` | MaxMind 官网（需注册） | 国家封禁的基础，做地域拦截必须有 |
| `GeoLite2-City.mmdb` | 同上 | 省 / 市 / 运营商 |
| `ip2region.xdb` | ip2region 开源仓库 | 国内属地细化，不依赖 MaxMind 账号 |

也可以在面板 **IP 属地** 页上传，上传时先校验文件头再原子替换，立即生效。

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
| 代理端口 | `80,443` | `NewUserConn` 回调参与判定的端口 |
| 可信回源网段 | 空 | 来自这些 CIDR 的访问按 `X-Forwarded-For` 判定，避免封掉 CDN 节点 |
| 总开关 | 开 | 关闭后只判定不写规则 |
| 观察模式 | 关 | 只记录不封禁，上线前验证误伤 |
| 日志级别 | `info` | `debug` / `info` / `warn` / `error` |
| 在线检查更新 | 开 | 关闭后面板不访问 GitHub，纯内网部署建议关掉 |
| 检查来源 | `dreamstation625/FrpFireWall` | 查询 Release 的 GitHub 仓库（`owner/name`） |

运行期策略（频次阈值、阶梯时长、地域封禁、速率限制）在 **频控策略** 页，改完即时生效，不用重启。

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

### 发版流程

版本号的唯一来源是仓库根目录的 `VERSION` 文件，发布 tag 必须与它一致，
不一致 CI 会直接失败——避免出现「tag 说 0.0.2、二进制里却编译进 0.0.1」这种查不出来的事故。

```bash
# 1. 改 VERSION 为要发布的版本号
echo "0.0.2" > VERSION
# 2. 提交
git add VERSION && git commit -m "chore: 发布 0.0.2"
# 3. 打同名 tag 推上去（v 前缀必需）
git tag v0.0.2 && git push origin main --tags
```

CI（`.github/workflows/release.yml`）会自动：校验 tag 与 `VERSION` 一致 →
过发布闸门 → 跑 `go vet` 与单元测试 → 构建前端 → 交叉编译 `linux/amd64` 与 `linux/arm64` →
实地跑一遍二进制确认版本号注入成功 → 生成 `sha256sums.txt` → 创建 Release。

tag 里带 `-pre.` 的会被自动标记为 **Pre-release**，不会成为 latest；
正式版则标记为 latest。发布物包含两个架构的二进制、校验和、`install.sh` 与 systemd 单元。

`VERSION` 的格式也由 CI 看门：写 `0.1.0-dev` 这类会被直接拒绝。

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
internal/model/       数据模型（ACL / 封禁 / 策略 / 事件）
internal/store/       GORM + 纯 Go SQLite 数据层
internal/firewall/    后端抽象与 iptables / nftables 驱动
internal/geoip/       双库属地解析（mmdb + xdb）
internal/guard/       判定引擎：滑窗计数、封禁、reconcile
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

- **只保护 frp 端口**，不动 ssh、web 等其它服务的规则。
- **不支持 CentOS / RHEL。** 目标是 Debian / Ubuntu 系；其它发行版理论上能编译，
  但 nftables 版本差异可能影响 per-IP 限速能力。
- **不支持 Docker 部署。** 改防火墙需要 `CAP_NET_ADMIN` 且要看到宿主机 netns。
- **单用户**，一个面板账号 + JWT，没有 RBAC。
- **属地库需自行准备**，MaxMind 有许可限制，不便随包分发。
- **防火墙规则的实际落盘未在真实 Linux 上验证过**（开发机是 Windows），
  上线前请用 `iptables-save` / `nft -a list ruleset` 核对，并演练一次救援脚本。
