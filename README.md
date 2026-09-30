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

5. **白名单是「豁免本程序封禁」，不是「全端口放行」。** 实现方式是在生成黑名单时把白名单
   地址减掉，不往内核写豁免规则。

6. **属地解析只在 IP 访问时实时进行**，不下沉成 ipset 之类的内核集合。库文件常驻内存，
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

把 `dist/frpfirewall-linux-amd64`、`scripts/install.sh`、`scripts/frpfirewall-panic.sh`、
`deploy/frpfirewall.service` 放到目标机器的同一个目录：

```bash
sudo ./install.sh -b ./frpfirewall-linux-amd64
```

脚本会装二进制、建数据目录、注册并启动 systemd 服务，最后打印初始化令牌。

### 3. 设置面板密码

打开 `http://<本机IP>:7930`，首次访问会跳到初始化页。填入启动时打印的令牌
（同时保存在 `/var/lib/frpfirewall/setup_token.txt`）并自行设置密码，令牌随即作废。

令牌是必需的：面板可能直接开在公网，不能靠"谁先来谁就是管理员"。

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
| 面板监听 | `127.0.0.1:7930` | 对外网开放用 `0.0.0.0:7930` |
| HTTPS | 关闭 | 面板暴露公网时开启，否则密码是明文传输 |
| 登录有效期 | 12 小时 | JWT token 的 TTL |
| 插件监听 | `127.0.0.1:9100` | 只允许回环，frps 必须同机 |
| bindPort | 7000 | frps 的 bindPort，用于下发连接速率限制 |
| 代理端口 | `80,443` | `NewUserConn` 回调参与判定的端口 |
| 可信回源网段 | 空 | 来自这些 CIDR 的访问按 `X-Forwarded-For` 判定，避免封掉 CDN 节点 |
| 总开关 | 开 | 关闭后只判定不写规则 |
| 观察模式 | 关 | 只记录不封禁，上线前验证误伤 |
| 日志级别 | `info` | `debug` / `info` / `warn` / `error` |

运行期策略（频次阈值、阶梯时长、地域封禁、速率限制）在 **频控策略** 页，改完即时生效，不用重启。

监听地址改错导致面板打不开时，可以用启动参数临时覆盖：
`frpfirewall -data /var/lib/frpfirewall -listen 127.0.0.1:7930`。

### 面板对外网开放的安全要求

- 开启 HTTPS，否则登录密码是明文传输
- 登录有防爆破：5 分钟窗口 8 次失败锁定 10 分钟
- 初始化令牌用完即废，不会留下固定口令

---

## 运维

### 出事了怎么救

误封导致连不上，或规则下发后网络异常：

```bash
sudo ./frpfirewall-panic.sh              # 清掉所有受管规则
sudo ./frpfirewall-panic.sh --dry-run    # 先看会做什么
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

## 开发

```bash
make web      # 构建前端到 internal/web/dist
make build    # 构建当前平台二进制
make test     # go vet + go build
make smoke    # 对已启动的实例跑接口冒烟测试
```

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
cmd/frpfirewall/      入口，命令行参数与装配
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
deploy/               systemd 单元
scripts/              安装与救援脚本
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
