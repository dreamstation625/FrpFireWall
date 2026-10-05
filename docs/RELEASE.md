# 🚀 版本与发布

[← 项目首页](../README.md) · [文档中心](README.md) · [开发与编译](DEVELOPMENT.md)

发布路径：**同步版本文件 → 提交到 main → 等 CI 通过 → 推送同名 tag → 自动生成 Release**。
面板只负责检查更新，实际升级使用[安装脚本](../README.md#升级与卸载)。

- [版本号格式](#版本号格式)
- [检查更新（面板侧）](#检查更新面板侧)
- [CI 分级](#ci-分级)
- [发版流程](#发版流程)
- [发布附件与验收](#发布附件与验收)
- [发布闸门](#发布闸门)

## 版本号格式

| 形态 | 含义 | 示例 |
| --- | --- | --- |
| `x.y.z` | 正式版 | `0.0.1` |
| `x.y.z-pre.NN` | 预发布版 | `0.0.1-pre.01` |

预发布序号从 `01` 起，**至少两位**；超过 `99` 可继续使用 `100`。
`-dev` / `-rc` / `-alpha` / `-beta` 等后缀不属于项目支持的版本格式。
同一号段内正式版大于预发布版：`0.0.1 > 0.0.1-pre.99`。

构建从 `VERSION` 读取待注入版本，但发布前需要同步四个文件：

| 文件 | 用途 |
| --- | --- |
| `VERSION` | Makefile 构建与 CI tag 校验的版本来源 |
| `internal/version/version.go` | 裸 `go build` 使用的默认版本 |
| `web/package.json` | 前端包版本 |
| `web/package-lock.json` | 锁文件版本（两处字段） |

使用 `scripts/version-bump.sh` 一次同步。后端测试会核对默认版本与 `VERSION`，漏改会导致 CI 失败。

## 检查更新（面板侧）

点击侧边栏底部版本号可打开版本信息对话框；发现新版本时顶栏显示红标。

| 当前版本 | 可提示的更新 |
| --- | --- |
| 正式版 | 更高的正式版 |
| 预发布版 | 更高预发布版或正式版；同号段正式版优先 |

例如 `0.0.1-pre.03 → 0.0.1` 会提示更新，正式版用户不会被引到 `-pre`。

检查通过 GitHub Releases API 完成，**只读，不下载或替换二进制**。
成功结果缓存一小时，失败结果缓存十分钟；无法访问 API 时对话框显示错误。
内网部署可在 **系统设置** 关闭检查更新。

## CI 分级

工作流为 `.github/workflows/ci.yml`，支持 `main` 推送、面向 `main` 的 PR 与手动触发。

| 范围 | 检查内容 |
| --- | --- |
| 日常提交 | `VERSION` 格式、`go mod tidy` 一致性、`go vet`、全量单元测试 |
| `web/` 发生变化 | 日常检查 + 平台专用依赖检查、`npm ci`、前端构建与产物检查 |
| `VERSION` 发生变化 | 上述前后端检查 + 安装脚本回归、版本脚本回归、Go 编译检查 |
| 无可靠比较基准 / 手动触发 | 按前端和版本均有变化处理，运行完整检查 |

`changes` job 比较提交范围，其他 job 根据结果决定是否运行。
前端在改动时就构建，脚本回归和额外编译检查跟随发版提交，避免问题留到打 tag 后才发现。

> [!NOTE]
> main 的完整 CI 和 Release 工作流并非完全相同：安装 / 版本脚本回归在 main 的发版档运行；
> Release 负责重新检查后端、构建前端、交叉编译、验证版本注入与发布附件。因此推 tag 前应先等 main CI 通过。

## 发版流程

以下为 Bash 示例，**先将目标版本改成严格高于所有已发布版本的新版本**。
每条命令执行成功、检查结果后再继续；不要在尚有无关工作区改动时使用 `git add -A`。

### 1. 同步版本文件

```bash
# 示例版本；按实际发布计划修改
FW_VERSION=0.0.2-pre.01
bash scripts/version-bump.sh "$FW_VERSION"
git diff -- VERSION internal/version/version.go web/package.json web/package-lock.json
```

### 2. 提交并推送 main

```bash
git add VERSION internal/version/version.go web/package.json web/package-lock.json
git commit -m "[更新] 版本升至 $FW_VERSION"
git push origin main
```

这段示例只暂存版本文件，待发布的功能改动应提前完成提交。
确认发布提交在 `main`，并在 Actions 中等待该提交的 CI 全绿。不要跳过前端构建或脚本回归失败。

### 3. 打 tag 并触发发布

```bash
git tag "v$FW_VERSION"
git push origin "v$FW_VERSION"
```

tag 必须带 `v` 前缀，去掉前缀后必须与该提交的 `VERSION` 完全一致。
`.github/workflows/release.yml` 随后执行：

```text
校验 tag / VERSION → 比较已发布最高版本 → 后端检查与测试
       → 前端构建 → Linux amd64 / arm64 编译 → 整理附件
       → 验证二进制版本与脚本语法 → 生成校验和 → 创建 Release
```

tag 含 `-pre.` 时标记为 **Pre-release**，不成为 latest；正式版标记为 latest。
Go 版本来自 `go.mod`，Node.js 使用 22 系列（本地需 ≥ 22.12.0），环境准备见[开发指南](DEVELOPMENT.md#环境)。

## 发布附件与验收

| 附件 | 作用 |
| --- | --- |
| `frpfirewall-linux-amd64` | x86-64 Linux 二进制，内嵌前端 |
| `frpfirewall-linux-arm64` | ARM64 Linux 二进制，内嵌前端 |
| `install.sh` | 在线 / 离线安装、更新、状态与卸载 |
| `frpfirewall-panic.sh` | 清理本程序受管规则的救援脚本 |
| `frpfirewall.service` | systemd 服务单元 |
| `sha256sums.txt` | 上述五个附件的 SHA-256 校验和 |

下载对应附件与校验和后，在下载目录验证：

```bash
sha256sum -c sha256sums.txt --ignore-missing
./frpfirewall-linux-amd64 -version
```

二进制若没有执行权限，先 `chmod +x frpfirewall-linux-amd64`；ARM64 机器换用对应文件。
`--ignore-missing` 只校验已下载附件，完整验收应下载全部五个文件并逐一比对。
版本打印不启动服务，不能替代真实 Linux 上的[防火墙验收](DEVELOPMENT.md#测试)。

发完后核对版本、架构、附件与 Pre-release / latest 标记。
仓库维护约定是 Actions 记录保留最近 10 条；如需清理，只删除已完成的运行记录，保留进行中的任务与所需故障证据。

## 发布闸门

候选版本必须**严格高于所有已发布 Release 中的最高版本**，才进入构建与发布。
未提升时打印 notice 并跳过，工作流仍可显示成功，应检查是否实际创建了新 Release。

| 场景 | 结果 |
| --- | --- |
| 再次推送已经发布的同名 tag | 跳过 |
| 推送比已发布最高版本更旧的版本 | 跳过 |
| 正式版已发布，再推同号段 `-pre` | 跳过 |
| 构建 / 发布失败，尚未创建 Release，重跑原 tag | 最高已发布版本仍低于候选时正常发布 |

比较基准是 **Release 列表**，不是已有 git tag，因此失败发布不会仅因 tag 已存在就永远被挡住。
若期间发布了更高版本，重跑旧 tag 仍会被跳过；无法获取比较基准时工作流失败，不盲目发布。

闸门程序在 `tools/versioncmp`，复用 `internal/version` 的比较逻辑，和面板检查更新保持一致。
失败后优先查看 Actions 的具体步骤与日志，修正后按版本规则重试；不要靠删除已发布 tag 来触发重跑。
