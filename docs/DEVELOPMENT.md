# 🛠️ 开发与编译

[← 项目首页](../README.md) · [文档中心](README.md) · [版本与发布](RELEASE.md) · [设计约束](DESIGN.md#design-constraints)

从准备工具到产出二进制，按下面的步骤即可完成本地开发。**编译产物内嵌前端；修改前端后必须重新构建并重新编译 Go。**

- [环境](#环境)
- [首次准备](#首次准备)
- [常用命令](#常用命令)
- [Windows（PowerShell）](#windowspowershell)
- [本地开发](#本地开发)
- [交叉编译与产物](#交叉编译与产物)
- [测试](#测试)
- [本机限制（Windows 开发机）](#本机限制windows-开发机)
- [代码结构](#代码结构)

## 环境

| 工具 | 项目要求 | 说明 |
| --- | --- | --- |
| Go | **≥ 1.26.4** | 以 `go.mod` 的 `go` 指令为准；CI 使用 `go-version-file: go.mod` |
| Node.js | **22.x，且 ≥ 22.12.0** | 与 CI 使用的 Node 22 系列一致；锁定的 `unplugin` 依赖要求 22.12.0 起 |
| npm | 随 Node.js 安装 | 使用 `web/package-lock.json` 固定依赖 |
| Git | 命令行可用 | 拉取源码与获取构建提交号 |
| Bash + GNU Make | 执行 `make` 时需要 | Makefile 指定 `/bin/bash`；原生 PowerShell 使用下方手动流程 |
| Python 3 + curl | 安装脚本回归测试时需要 | 脚本调用 `python3`、`curl`，还需要 Bash 与 GNU 工具（如 `sha256sum`） |
| Linux 防火墙环境 | 实际规则验证时需要 | Debian / Ubuntu、systemd、iptables（含 ip6tables）或 nftables，具备相应权限 |

后端使用 **Gin + GORM + 纯 Go SQLite**，前端使用 **Vue 3 + TypeScript + Vite + Element Plus + Pinia + ECharts**。
SQLite 无需单独安装服务，`CGO_ENABLED=0` 构建无需 C 编译器。

只改后端且已有可用前端产物时，可以不安装 Node.js；**首次构建完整控制台仍需要 Node.js 和 npm**。
部署已经编译好的二进制时，无需 Go / Node.js / npm。

## 首次准备

```bash
git clone https://github.com/dreamstation625/FrpFireWall.git
cd FrpFireWall
go mod download
cd web
npm ci --no-audit --no-fund
cd ..
```

开始前可用 `go version`、`node --version`、`npm --version` 确认工具已在 PATH 中。
`npm ci` 严格按锁文件安装；依赖清单与锁文件不一致时会失败，应先核对两者再构建。

## 常用命令

在仓库根目录、Bash 环境中执行：

| 命令 | 做什么 | 输出 / 前提 |
| --- | --- | --- |
| `make version` | 读取 `VERSION` | 显示待注入的版本号 |
| `make web` | 安装前端依赖并构建 | `internal/web/dist/` |
| `make build` | 先 `make web`，再编译当前平台 | `dist/frpfirewall` |
| `make release` | 先构建前端，再交叉编译 | Linux amd64 / arm64 二进制及校验和 |
| `make test` | 单元测试、`go vet`、编译检查 | 不启动服务，不构建前端 |
| `make smoke` | 接口冒烟测试 | 需要已启动的专用测试实例 |
| `make version-bump V=x.y.z` | 同步四处版本文件 | 格式与发版步骤见[发布指南](RELEASE.md) |

`make web` 当前使用 `npm install`；CI 使用 `npm ci`。需要严格复现锁定依赖时，可使用首次准备和下方手动构建步骤。

## Windows（PowerShell）

无需安装 Make。在仓库根目录依次执行，**每一步成功后再继续**。

### 1. 构建前端

```powershell
go mod download
Push-Location web
npm ci --no-audit --no-fund
npm run build
Pop-Location

# Vite 会清空输出目录；补回受版本控制的占位文件
New-Item -ItemType File -Force internal/web/dist/.gitkeep | Out-Null
```

前端输出到 `internal/web/dist/`。确认 `index.html` 存在，再编译后端。

### 2. 编译并注入版本信息

```powershell
New-Item -ItemType Directory -Force dist | Out-Null
$fwModule = "github.com/dreamstation625/FrpFireWall"
$fwVersion = (Get-Content VERSION -Raw).Trim()
$fwCommit = git rev-parse --short HEAD
$fwBuiltAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$fwLdflags = "-s -w -X $fwModule/internal/version.Version=$fwVersion -X $fwModule/internal/version.Commit=$fwCommit -X $fwModule/internal/version.BuildTime=$fwBuiltAt"

# 以下变量只影响当前终端；开发机编译目标显式设为 Windows
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = go env GOHOSTARCH
go build -trimpath -ldflags $fwLdflags -o dist/frpfirewall.exe ./cmd/frpfirewall
./dist/frpfirewall.exe -version
```

`-version` 只打印版本后退出，不启动面板、不写防火墙规则。
直接 `go build` 会使用源码中的默认版本号；上面的步骤与 Makefile 一样注入 `VERSION`、提交号与 UTC 构建时间。

### 3. 在 Windows 上生成 Linux 产物

沿用上一步的 `$fwLdflags`，在同一个终端执行：

```powershell
try {
    $env:GOOS = "linux"
    foreach ($fwArch in @("amd64", "arm64")) {
        $env:GOARCH = $fwArch
        go build -trimpath -ldflags $fwLdflags -o "dist/frpfirewall-linux-$fwArch" ./cmd/frpfirewall
        if ($LASTEXITCODE -ne 0) { throw "Linux $fwArch 构建失败" }
    }
} finally {
    # 回到开发机目标，避免下一次测试继续使用 Linux 目标
    $env:GOOS = "windows"
    $env:GOARCH = go env GOHOSTARCH
}
```

Linux 产物需要复制到 Linux 上运行。PowerShell 手动流程只生成二进制，不自动整理发布附件或生成 `sha256sums.txt`。

## 本地开发

### 后端与插件

先完成前端和当前平台二进制构建，再使用**独立测试数据目录**启动。

Linux / Bash：

```bash
./dist/frpfirewall -data testdata/data -listen 127.0.0.1:7930
```

Windows / PowerShell：

```powershell
./dist/frpfirewall.exe -data testdata/data -listen 127.0.0.1:7930
```

启动后按日志中的一次性令牌完成初始化。面板地址为 `http://127.0.0.1:7930`，插件监听 `127.0.0.1:9100`。
Windows 无真实 iptables / nftables 后端，只适合验证管理接口与应用层逻辑。
在具备防火墙后端的 Linux 上，实例可能下发规则，请使用专用测试机器。

### 前端热更新

另开终端，在仓库根目录执行：

```bash
cd web
npm run dev
```

默认地址 `http://localhost:5173`，`/api` 请求代理到 `http://127.0.0.1:7930`，详见 `web/vite.config.ts`。
开发服务器直接读取前端源码，修改页面可热更新；它不更新二进制里的静态资源。

## 交叉编译与产物

```text
web/ 源码
   │ npm run build
   ▼
internal/web/dist/ 静态资源
   │ go:embed + go build（CGO_ENABLED=0）
   ▼
dist/ 二进制
```

| 构建方式 | 输出 | 内容 |
| --- | --- | --- |
| `make build` | `dist/frpfirewall` | 当前平台可执行文件，内嵌前端 |
| `make release` | `dist/frpfirewall-linux-amd64`、`dist/frpfirewall-linux-arm64` | 两种 Linux 架构与二进制校验和 |
| GitHub Release 工作流 | 二进制、`install.sh`、`frpfirewall-panic.sh`、`frpfirewall.service`、`sha256sums.txt` | 完整分发包，校验和覆盖全部附件（校验和文件自身除外） |

仓库只跟踪 `internal/web/dist/.gitkeep`，它让 `go:embed all:dist` 在首次克隆后仍能编译。
**编译成功不代表控制台可用**：打包前必须构建出真正的 `index.html` 与资源文件。
Vite 的 `emptyOutDir: true` 会清理该输出目录，`make web` 会自动补回 `.gitkeep`。

## 测试

### 后端检查

无 Make 时，在仓库根目录逐条执行：

```bash
go test ./... -count=1
go vet ./...
go build ./...
```

覆盖包括版本比较与更新筛选、策略判定、封禁与到期、规则生成、计数解析、接口参数校验等。
这些检查不等同于真实 Linux 防火墙验证。

### 脚本回归

```bash
bash testdata/test-install.sh
bash testdata/test-version-bump.sh
```

安装脚本测试使用**本地假 GitHub Releases 服务与桩命令**，在临时目录运行安装、升级、回滚与卸载，
不操作真实系统目录或防火墙。版本脚本测试在临时沙盒里校验四处版本同步，不修改仓库版本文件。
需要 Python 3、curl、Go、Bash 与 GNU 工具；Windows 可使用配置好这些工具的 Git Bash / MSYS 环境。

### 接口冒烟

```bash
bash testdata/smoke.sh
```

脚本默认请求 `127.0.0.1:7930` / `127.0.0.1:9100`，读取 `testdata/data` 中的初始化令牌，
并使用脚本内固定的测试密码。它会修改策略、名单与配置；只用于专用测试实例。
迁移到其他机器时还需核对脚本中的 PATH 设置。通过接口冒烟也不能证明内核封禁已经生效。

### 几条约定

- `gofmt -w` 只列本次修改的具体 Go 文件，避免把无关格式化混进改动。
- 改 JSON tag 时同时检查按字符串 key 取值的测试与前端引用；编译不会发现所有字段错配。
- 回归测试应能挡住原始问题，确认旧实现会失败；不要只断言正常路径。
- 真实规则验证在 Debian / Ubuntu 上执行，使用 `iptables-save` / `nft -a list ruleset` 核对，并演练[救援流程](TROUBLESHOOTING.md#误封导致连不上)。

## 本机限制（Windows 开发机）

Windows 可编译后端、构建前端和运行部分应用层验证；**没有 Linux 防火墙后端**，无法证明封禁、解封或内核计数生效。
真实 Linux 规则落盘仍需单独验收，见[设计文档中的验证边界](DESIGN.md#9-开发计划已完成)。

GeoIP 的 `.xdb` / `.mmdb` 文件不随仓库分发。真实属地行为需要先在面板 **IP 属地** 页下载或上传数据库。

若自动化环境拦截 Vite 对输出目录的批量清理，可在 `web/` 下临时使用：

```bash
npm run build -- --outDir ../tmp/webcheck --emptyOutDir
```

这里只用于验证前端构建，**不会更新 `internal/web/dist`，也不会更新二进制里的控制台**。
正常环境继续使用标准构建；受限环境不要绕过删除保护。

## 代码结构

```text
FrpFireWall/
├── VERSION                 版本号来源，CI 校验 tag 与它一致
├── cmd/frpfirewall/         程序入口、命令行参数与服务装配
├── internal/
│   ├── api/                REST API 与 JWT 鉴权
│   ├── config/             配置模型与 SQLite 持久化
│   ├── model/              名单、封禁、策略、事件等模型
│   ├── store/              GORM + 纯 Go SQLite 数据层
│   ├── firewall/           iptables / nftables 驱动、探测与计数解析
│   ├── guard/              判定引擎、滑窗、细分规则、封禁与同步
│   ├── geoip/              MaxMind Country / City + ip2region 属地解析
│   ├── frpsplugin/         frps httpPlugins 协议实现
│   ├── portrange/          端口区间解析与后端渲染
│   ├── myip/               服务器出口 IP 探测与缓存
│   ├── version/            版本号注入、解析与比较
│   ├── update/             GitHub Releases 更新检查
│   └── web/                go:embed 前端产物
├── web/                    Vue 3 + Vite 前端源码
├── tools/versioncmp/       发布闸门程序
├── scripts/                安装、救援、版本同步脚本
├── deploy/                 systemd 单元
├── testdata/               冒烟、脚本回归与辅助工具
├── .github/workflows/      CI 与 tag 发布流程
└── docs/                   使用、开发、发布与设计文档
```

下一步：[发布流程](RELEASE.md) · [核心设计决策](DESIGN.md#decision-index)
