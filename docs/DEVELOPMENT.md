# 开发

- [环境](#环境)
- [常用命令](#常用命令)
- [测试](#测试)
- [本机限制（Windows 开发机）](#本机限制windows-开发机)
- [代码结构](#代码结构)

---

## 环境

- Go 1.26+
- Node 20+（只改后端的话不需要）
- 需要 `make`（Windows 上没有的话直接照下面跑 `go` / `npm` 命令）

## 常用命令

```bash
make version  # 显示将要编译进二进制的版本号（读 VERSION 文件）
make web      # 构建前端到 internal/web/dist
make build    # 构建当前平台二进制
make release  # 交叉编译 linux/amd64 与 linux/arm64，产物在 dist/
make test     # 单元测试 + go vet + go build
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

## 测试

```bash
go test ./...
```

单元测试覆盖版本号解析 / 比较 / 更新筛选（`internal/version`）与更新检查的缓存、
轨道规则、失败降级（`internal/update`）等。

一键脚本有自己的回归测试。它会起一个**假 GitHub Releases 服务**，用桩命令替换
`systemctl` / `iptables` / `install` / `uname` / `id`，在临时目录里真的跑一遍
安装 → 升级 → 回滚 → 卸载，并把脚本里的版本比较逻辑与 Go 侧逐条对照：

```bash
bash testdata/test-install.sh
```

全程不碰真实的 `/usr/local/bin`、`/etc/systemd/system` 与本机防火墙，不需要 root。

版本脚本同样有回归测试：

```bash
bash testdata/test-version-bump.sh
```

`testdata/smoke.sh` 是对着**已启动实例**跑的接口冒烟：

```bash
bash testdata/smoke.sh
```

### 几条约定

- 提交前 `gofmt -w` **只列具体文件，不要给目录** —— HEAD 上本就有几个文件没格式化
  干净，目录级 `-w` 会把无关改动混进 diff。CI 只跑 `go vet` 不查 gofmt。
- 改 JSON tag 要连字符串形式一起搜：按字符串 key 取值的引用点（测试里的
  `strOf(m, "from")`、前端的 `data.xxx.tag`）不会因改名而编译失败，只会在运行时
  拿不到值。改完直接跑 `go test ./...` 全量最稳，只跑改动所在的包会漏。
- 新测试要能"临时回退就 FAIL"：只断言正常路径的用例挡不住回归，写之前先把实现
  回退一次确认它真的会红。

## 本机限制（Windows 开发机）

- **不跑接口 / 防火墙端到端测试**，也不起本地实例。功能验证走单测（失败路径与参数
  校验，不触网）+ 真实网络下直接调函数。
- 仓库里没有 xdb / mmdb 库文件（`testdata/data/` 只有 sqlite）。要验属地相关的真实
  行为，先用 `GET /geoip/sources` + `POST /geoip/download` 下一份。
- **`npm run build` 跑不完整**：vite 的 `emptyOutDir` 要删 `internal/web/dist/assets`
  里 50+ 个文件，会被沙箱的批量删除保护拦下。**不要绕过这道防护**，改成出树构建：
  `cd web && npx vite build --outDir /tmp/webcheck --emptyOutDir`。
  代价是 `internal/web/dist` 留在旧产物、`.gitkeep` 被删（`git checkout --` 恢复），
  真实构建交给 CI 的前端 job 与 `make web`。
- 没有 `make`：`make test` 跑不了，直接跑
  `go test ./... && go vet ./... && go build ./...`。
- 防火墙规则与计数解析只验过输出样本，没在真实 Linux 上跑过；上线前用
  `iptables-save` / `nft -a list ruleset` 核对一遍。

## 代码结构

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
internal/myip/        服务器出口 IP 探测（第三方回显 + 缓存）
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
  version-bump.sh     版本号四处一起改
testdata/
  smoke.sh            接口冒烟测试（对着已启动的实例跑）
  test-install.sh     一键脚本回归测试（假 Release 服务 + 桩命令，全离线）
  test-version-bump.sh 版本脚本回归测试（临时沙盒）
  fake-release-server.py
docs/
  DESIGN.md           设计决策（D1…D30，按编号追加）
  FEATURES.md         功能详解
  TROUBLESHOOTING.md  排障
  DEVELOPMENT.md      本篇
  RELEASE.md          发版流程与发布闸门
```
