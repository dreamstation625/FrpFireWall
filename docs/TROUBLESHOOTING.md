# 🧭 排障指南

[← 项目首页](../README.md) · [文档中心](README.md) · [功能详解](FEATURES.md)

按「现象 → 定位 → 处理」组织。先定位再动手，尤其是监听地址这类问题：
猜错方向的话，改半天改的是根本没生效的那一处。

## 先按现象定位

| 现象 | 优先检查 | 跳转 |
| --- | --- | --- |
| 面板完全打不开 | 服务状态、实际监听地址、启动参数覆盖 | [面板打不开](#面板打不开) |
| 升级后外网仍无法访问 | 旧数据库监听值与 systemd drop-in | [旧版本监听地址](#旧版本升级后的监听地址) |
| 忘记管理员密码 | 在本机重置密码字段，再凭新令牌初始化 | [密码恢复](#忘记面板密码) |
| 某个 IP 被拦或未按预期拦截 | 排障查询与固定判定顺序 | [判定链路](#某个地址为什么被拦--没被拦) |
| 下发规则后 SSH / 隧道异常 | 先停服务，再预览并清理受管规则 | [紧急救援](#误封导致连不上) |

服务状态与最近日志：

```bash
sudo systemctl status frpfirewall --no-pager
sudo journalctl -u frpfirewall -n 100 --no-pager
```

## 本页导航

- [面板打不开](#面板打不开)
- [忘记面板密码](#忘记面板密码)
- [某个地址为什么被拦 / 没被拦](#某个地址为什么被拦--没被拦)
- [误封导致连不上](#误封导致连不上)

---

## 面板打不开

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

<a id="旧版本升级后的监听地址"></a>

### ⚠️ 从 0.0.1-pre.02 及更早升上来的，监听地址不会自动变

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
sudo systemctl daemon-reload
sudo systemctl restart frpfirewall

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

---

## 忘记面板密码

把数据库 `settings` 表里的 `admin_password_hash` 置空后重启，会重新进入初始化流程：

以下命令在服务器本机执行，需要管理员权限与 `sqlite3` 工具。先停止服务并备份数据库，
同时清除残留初始化令牌，确保下次启动生成新令牌。

```bash
sudo systemctl stop frpfirewall
sudo cp -p /var/lib/frpfirewall/frpfirewall.db "/var/lib/frpfirewall/frpfirewall.db.backup-$(date +%Y%m%d-%H%M%S)"
sudo sqlite3 /var/lib/frpfirewall/frpfirewall.db \
  "BEGIN; UPDATE settings SET value='' WHERE key='admin_password_hash'; UPDATE settings SET value='' WHERE key='setup_token'; INSERT INTO settings(key,value) VALUES('auth.session_version',lower(hex(randomblob(32)))) ON CONFLICT(key) DO UPDATE SET value=excluded.value; COMMIT;"
sudo systemctl start frpfirewall
```

重启后服务会**重新生成一个令牌**（旧的已作废），启动时打印、同时写进
`/var/lib/frpfirewall/setup_token.txt`，所以 `journalctl -u frpfirewall` 和这个文件
都能拿到。

---

## 某个地址为什么被拦 / 没被拦

面板 **封禁记录 → 排障查询**：输入一个 IP，返回它当前的状态
（白名单 / 黑名单 / 已封禁 / 可信回源 / 系统保护）、窗口内命中次数与命中原因。

判定顺序是固定的（`internal/guard/judge.go`），查的时候按这个顺序对，
**排在前面的先返回**：

| 顺序 | 判定 | 命中结果 |
| --- | --- | --- |
| 0 | 系统保护地址（回环 / 内网 / 链路本地） | 放行，不参与后面任何判定 |
| 1 | 白名单（IP 条目与地区条目同权） | 放行 |
| 2 | 手动黑名单 | 拒绝 |
| 2b | 地区黑名单条目 | 拒绝，并把**这个 IP** 封进内核 |
| 3 | 活跃封禁 | 拒绝，回给 frpc 剩余时间 |
| 4 | 可信回源网段（CDN / 反代） | 放行，跳过后续封禁决策 |
| 5 | 全局 GeoIP 国家名单 | 拒绝 + 封禁；**细分规则取代不了它** |
| 6 | 频控细分规则（第一条命中的） | 「直接拦截」则拒绝 + 封禁；否则取代全局频控参数 |
| 7 | 窗口计数 → 阈值 → 限速 | 超速尝试也计入窗口；先判阈值封禁，再判独立限速 |

上表描述正常执行模式。观察模式放行自动策略并记录「策略观察」，但人工地址黑名单和人工封禁
继续拦截；关闭自动封禁不新增持久记录，地区 / 直接拦截仍拒绝当次连接，频次阈值仅记录，
独立限速继续执行。详见[开关行为](FEATURES.md#观察模式与自动封禁)。

两点容易误判：

- **可信回源排在封禁之后**，所以"来自 CDN 节点"不能救一个已被黑名单或已封禁的地址，
  它只是不再往后面累加计数。
- **全局国家名单排在细分规则之前**，细分规则取代的只有"频控参数"（窗口 / 阈值 / 限速 /
  阶梯），取代不了名单类判定，也取代不了自动封禁、观察模式这类行为开关。

被地区条目拦下的，内核里只有**那个具体 IP** 的规则（地区条目本身不产生内核规则），
所以 `iptables-save` / `nft list ruleset` 里看不到"某国"这种条目是正常的。

---

## 误封导致连不上

规则下发后网络异常，或确认误封：

```bash
sudo systemctl stop frpfirewall     # 必须先停，否则会被 reconcile 重新下发
sudo frpfirewall-panic --dry-run    # 先看会做什么
sudo frpfirewall-panic              # 执行清理，核对输出中的失败提示
```

它只处理归属 frpfirewall 的跳转、链，以及注释以 `frpfirewall:` 开头的 nftables 规则、限速子链与
`frpfirewall_*` 集合，不动系统原有规则。

> [!IMPORTANT]
> 脚本先摘入口，再清空并删除 `FRPFIREWALL_GUARD`、`FRPFIREWALL_BLACK`、
> `FRPFIREWALL_BLACK_FRP`，并清理 nft 受管规则、限速子链与集合。
> 任一清理失败会返回非零；仍须检查失败提示与实际规则输出。

救援脚本只清网络层，应用层的封禁记录还在数据库里 —— 要彻底放行，还得去
**封禁记录** 页解封，或把对应的名单条目 / 规则停用。

处理完来源后再启动服务，并核对连接与内核规则；数据库中仍活跃的封禁会在启动时重新下发。

```bash
sudo systemctl start frpfirewall
sudo journalctl -u frpfirewall -n 50 --no-pager
```

需要反馈问题时，请附上版本、系统与防火墙后端、复现步骤、相关日志；分享前遮住初始化令牌、JWT、密码等信息。

## 修复后的认证与传输行为

- 改密码或登出后，旧 token 会被服务器撤销；单管理员面板的登出会撤销全部会话，重启也不会恢复。
- CSV 导出由面板携带认证头下载，不接受 URL 中的 token。旧脚本请改用 `Authorization: Bearer ...`。
- 面板以实际 TCP 对端限流，不信任客户端提供的转发头。放在反向代理后时，各客户端会共享该代理的登录限制。
- 普通请求上限 1MiB，名单导入 8MiB；属地上传单文件 200MiB，完整请求允许额外 1MiB 表单开销。
- 属地上传与同步下载使用独立 13 分钟传输截止时间；上游下载总预算仍为 12 分钟。反向代理自身的超时也应匹配。
- 切换后端会清理旧受管拦截规则；失败会返回错误，检查同步状态，不要据此假定切换已成功。
