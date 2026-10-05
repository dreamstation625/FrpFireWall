# 📚 FrpFireWall 文档中心

[← 返回项目首页](../README.md)

安装使用、策略配置、开发编译与架构维护，都从这里开始。

## 按任务阅读

| 我想做什么 | 从哪里开始 | 接着看 |
| --- | --- | --- |
| 安装并接入 frps | [快速开始](../README.md#quick-start) | [运行配置](../README.md#配置) |
| 配置频控、名单和地区拦截 | [功能详解](FEATURES.md) | [封禁范围](FEATURES.md#黑名单的封禁范围) |
| 面板打不开或忘记密码 | [排障指南](TROUBLESHOOTING.md) | [监听地址与启动覆盖](TROUBLESHOOTING.md#面板打不开) |
| 查误封并恢复连接 | [判定顺序](TROUBLESHOOTING.md#某个地址为什么被拦--没被拦) | [紧急救援](TROUBLESHOOTING.md#误封导致连不上) |
| 在 Windows / Linux 上开发 | [开发与编译](DEVELOPMENT.md) | [测试与验证边界](DEVELOPMENT.md#测试) |
| 打包并发布新版本 | [版本与发布](RELEASE.md) | [发布闸门](RELEASE.md#发布闸门) |
| 修改判定或防火墙行为 | [关键设计约束](DESIGN.md#design-constraints) | [设计决策索引](DESIGN.md#decision-index) |

## 文档分工

| 文档 | 主要内容 |
| --- | --- |
| [项目 README](../README.md) | 项目能力、安装接入、配置速查、开发环境与运行边界 |
| [FEATURES.md](FEATURES.md) | 配置方式、应用层 / 内核落点、规则口径和 GeoIP |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | 按现象定位、密码恢复、判定顺序与误封救援 |
| [DEVELOPMENT.md](DEVELOPMENT.md) | 工具版本、首次准备、PowerShell / Make 构建、测试和代码结构 |
| [RELEASE.md](RELEASE.md) | 版本同步、CI 分级、发布步骤、附件与发布闸门 |
| [SECURITY_REVIEW.md](SECURITY_REVIEW.md) | 本轮问题核实、修复对照与隔离验证 |
| [DESIGN.md](DESIGN.md) | 架构、D1–D30 决策、数据与 API 设计、历史验证记录 |

## 阅读时留意

- **配置的落点**：带端口条件的限速在内核执行；地区与代理名在插件回调里判定。
- **封禁的范围**：自动封禁固定全端口，手动黑名单可选范围。白名单豁免本程序封禁，不授予全端口访问权。
- **验证的边界**：编译、规则文本单测、接口冒烟与真实 Linux 内核验收是不同层次；历史测试结果不能替代当前版本验收。

维护文档时，命令与默认值应对应当前源码和工作流；更新标题后同时检查其他文档中的锚点链接。
