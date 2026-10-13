# 谛听（Diting）
**基于 eBPF 的 Linux 主机安全监控 Agent：内核级文件完整性监控（FIM）+ 全量运行时遥测 + AI 工作负载防护**

> eBPF-based Linux host security agent: File Integrity Monitoring (FIM),
> full runtime telemetry (process / network / privilege / namespace events),
> GPU & AI workload protection for private LLM clusters — near-zero overhead,
> event-driven, MITRE ATT&CK mapped.

适配等保2.0、服务器运维、工控、容器安全、云主机与 AI 工作负载防护场景。
项目正从「eBPF LSM FIM 工具」演进为「云安全与 AI 安全监控 Agent」。

## 核心功能

- **基线快照管理**：文件哈希/权限/属主采集入 SQLite，可信基准全生命周期管理（snapshot / list / delete / check / clean）
- **实时文件监控双模式**：纯 YAML 规则监控；基线监控模式（开机自检 + 实时篡改校验，区分存量风险与运行时入侵）
- **运行时遥测**：网络 connect/accept/bind 五元组、DNS 查询域名、权限事件（setuid/capset/ptrace/内核模块）、命名空间事件（mount/unshare/setns），全部携带进程归属与容器 ID，JSON 结构化输出
- **规则检测引擎**：规则 DSL v1 + 解析/匹配引擎，core 规则包覆盖执行类（TA0002）与凭据类（TA0006）攻击手法，配套 14 个攻击用例端到端验证与日常操作误报扫描
- **资产清点**：五类主机资产落库 + AI 资产发现——GPU 统一接口（NVIDIA 已适配，昇腾/海光预留）、模型文件识别（扩展名+魔数双判）、AI 进程三特征识别（cmdline / maps / 环境变量）
- **告警降噪与外发**：四级 severity + min_level 路由 + 静默窗口 + 外发侧窗口聚合（实测降幅 99.88%，落库逐条不受影响），钉钉/异步 webhook 渠道，失败重试不影响落库
- **合规交付**：HTML 审计报表、告警历史查询、事件汇总导出
- **低资源开销**：事件驱动无轮询，遥测开关默认关闭、对既有功能零影响；10k/s 事件零丢失，常态 CPU 均值 0.57%、RSS 峰值 139MB（全功能口径）

## 快速上手

```bash
make                                                # 编译
sudo ./diting baseline snapshot /etc        # 采集基线
sudo ./diting baseline check                # 离线核查
sudo ./diting monitor --db baseline.db -c config.yaml   # 实时监控
```

开启遥测（`baselines/default.yaml` 中 `telemetry.network/dns/privilege` 置 true）后：

```bash
sudo ./diting monitor -c baselines/default.yaml
curl -s http://example.com -o /dev/null   # → network.connect
dig example.com                            # → network.dns
sudo -u nobody id                          # → priv.setuid
```

## 文档与帮助

| 文档 | 内容 |
|------|------|
| [docs/help/index.html](docs/help/index.html) | **帮助中心**（浏览器打开） |
| [docs/help/fim-guide.html](docs/help/fim-guide.html) | FIM 完整使用手册：子命令参数、双模式、告警规则、钉钉配置 |
| [docs/help/telemetry-guide.html](docs/help/telemetry-guide.html) | 遥测手册：开关、采集点、事件字段、触发验证、已知限制 |
| [docs/kernel-compat-matrix.md](docs/kernel-compat-matrix.md) | 采集点内核兼容矩阵（4.18 / 5.4 / 5.10 / 6.x） |
| [docs/ring_buffer_optimization.md](docs/ring_buffer_optimization.md) | ring buffer 水位背压优化 |

## 目录结构

```
├── src/            # 用户态：baseline(FIM+遥测消费) / alerts / storage / cli / ops / common
│                   # asset(资产清点+AI资产发现) / detect(规则DSL引擎)；预留：ai(M4) / ebpf
├── manager/        # [M9 预留] 管理中心（企业版）
├── bpf/            # lsm_file / net_watch / priv_watch 探针 + 完整版 vmlinux.h（CO-RE）
├── rules/          # core 规则包（执行/凭据类）+ examples + perf/storm 压测规则
├── docs/           # 帮助中心(help/) + 兼容矩阵 + 设计文档 + 开发日志
├── tests/          # unit / integration / attack-cases(14 个攻击用例) / perf / fixtures
└── Makefile
```

## 内核版本要求

| 内核 | 能力 |
|------|------|
| ≥5.8 | 全功能：文件监控（可阻断）+ 遥测（network/dns/privilege/store）+ 进程树富化 |
| 5.7 | 文件监控（perf buffer，可阻断）；无遥测、无水位背压 |
| 5.4~5.6 | 文件监控（kprobe，仅告警无阻断）；无遥测 |
| 4.18（RHEL8 系） | 设计目标，待实测（依赖 BTF backport，当前版本拒绝 <5.4 启动） |
| <5.4 | 不支持 |

遥测功能需内核 ≥5.8（ring buffer 依赖）；详见 [docs/kernel-compat-matrix.md](docs/kernel-compat-matrix.md)。

## 技术栈与环境

C++17 · libbpf CO-RE（LSM BPF / kprobe / tracepoint）· yaml-cpp · SQLite（WAL）· spdlog · nlohmann/json
推荐内核 5.10+/6.x；4.18、5.4 降级路径见兼容矩阵。开发验证环境：Ubuntu 24.04，clang 18，libbpf 1.3。

## 版本与路线图

- ✅ **v0.3 已冻结**：FIM 全量功能（基线子命令、双模式监控、三类告警隔离、HTML 报表）
- ✅ **运行时遥测已入库**：网络/DNS/权限/命名空间事件 + 容器归属（内核 6.x/7.0 实测验收）
- ✅ **事件总线 + 落库管道**：10k/s × 5min 用户态零丢失，丢点计数全暴露
- ✅ **资产清点（M1）**：主机五类资产 + GPU/模型文件/AI 进程识别，`asset collect/list` 子命令
- ✅ **规则检测（M3 引擎）**：规则 DSL v1 端到端可用，core 规则包 8 条 + 误报扫描口径建立（W6 D1：日常操作仅 1 条已知双义误报）
- ✅ **告警外发链路**：severity 分级 / 路由 / 静默 / 聚合四层降噪（外发降幅 99.88%，三方对账误差 0）
- 🔄 **迭代中**：core 规则包扩充至 20+ 条、CIS 40 项接入 check 引擎、AI 告警升级（设计已定稿）、管理中心（M9）

## 商业服务与许可证

企业定制与等保交付服务：邮箱 kabc005009@163.com · 微信 houduankf · [知乎](https://zhihu.com/people/q1w2e3r4t5y6-86)

本项目采用 [Business Source License 1.1](LICENSE)（BSL 1.1），商标见 [TRADEMARK.md](TRADEMARK.md)：

| 使用场景 | 是否免费 |
|---|---|
| 个人学习、研究、开发测试、内部评估、参与贡献 | ✅ 免费 |
| 公司生产环境部署 / 集成进对外销售产品 | ❌ 需购买商业许可 |
| 发布满 3 年的历史版本 | ✅ 自动转为 GPLv2+ |
