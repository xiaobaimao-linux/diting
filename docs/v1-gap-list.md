# v1.0 差距清单（方案 A 预排，W8–W14）

> 日期：2026-10-13。**本文档为方案 A 预排，未拍板**——v1.0 范围三方案（docs/v1-scope-options.md）尚未拍板，
> 本清单只对位方案 A，不做推荐、不构成承诺。
> 依据：docs/v1-scope-options.md §方案 A、docs/kernel-compat-matrix.md（§2 主矩阵 / §4 待实测清单 / §6 冒烟实测）、
> docs/rule-engine-gaps.md（G1–G21）、calibration-w4/w5/w6 与 W7 交付口径。

## 1. 结论先行

方案 A 的五大件（遥测、FIM、规则引擎、CIS、攻击用例检出）**已全部提前落地且超额**；
剩余差距集中在方案 A 独有的两块**内核类硬骨头**：**perf buffer 降级版**（priv_watch/net_watch/proc_watch
事件通道）与**三系统兼容矩阵实测**（RHEL8/4.18、5.10/6.x 真机）。按方案 A 原口径出口在 W18（距今 12 周），
本文按任务要求只排 W8–W14 共 7 周主体工作，**W15–W18 为回归加固与发布缓冲，本文不展开**。

## 2. 当前进度对位：方案 A 范围内已提前完成项

| 项 | 完成周 | 证据 / 口径 |
|---|---|---|
| 遥测五类事件全链路（exec/network/dns/privilege/ns） | W2 | docs/dev-log-w2.md，进程链缺失率 0% |
| FIM 进程上下文富化 + 进程白名单 SIGHUP 热加载（M0-1/M0-2） | W3 | docs/dev-log-w3.md |
| 5.4 档冒烟：BTF 实测存在、lsm_kprobe 加载 attach 5/5、降级分支遥测静默缺失提示补齐 | W3（2026-09-29） | kernel-compat-matrix.md §6；待实测清单 #2 关闭、#3 的 5.4 半关闭 |
| 性能四指标收口（吞吐/RSS/CPU 达标，P99 归因降级记录） | W4 | docs/calibration-w4.md §3 |
| 规则引擎 DSL v1 + 解析器 + 匹配引擎 | W4 | docs/calibration-w4.md §1 |
| 通知体系：INotifier + webhook 异步 dispatcher（级别路由/静默/聚合，sent/failed/suppressed/merged 计数对账误差 0） | W5 | docs/calibration-w5.md，聚合降幅 99.88% |
| AI 资产发现（GPU/模型文件/AI 进程识别落库，PRD v1.0 M1 口径内） | W5 | docs/calibration-w5.md，提前 5 周启动 |
| core 规则包 16 条 + 22 攻击用例两轮回归 | W6 | docs/dev-log-w6.md |
| CIS 基线 40 项全判定引擎 + cis check/report + HTML/JSON 报告（等保 2.0 映射） | W6 | cis/cis-baseline-v1.yaml、docs/cis-baseline-v1.md |
| AI 告警升级（升一级封顶 critical，severity_origin/ai_boost 落库可审计） | W6 | 单测 13/13 |
| 规则包扩至 24 条（含挖矿 M3-4 / 防御规避 M3-5）+ 30 用例检出率 100%（超 ≥90% 口径） | W7 | tests/attack-cases/run_all.sh、docs/fpr-w7d3.md |
| G16 单实例锁（flock）、G17 加载器 fail-fast、G6 DSL 文件规则 inode 自动登记（含 G18 加载期警告） | W7 | docs/rule-engine-gaps.md 各条决策记录 |
| schema 债务清零：G10/G15 修复、G8 定口径（单命中为显式设计）、G9 定降级方案（inode_setattr 钩子，排 W10 后） | W7 | 同上 |

## 3. 方案 A 范围内剩余差距（W8 起的待办池）

1. **perf buffer 降级版未实现**（最大缺口，内核类工作）：priv_watch/net_watch 的 perf 通道未开发，
   proc_watch 同为 ringbuf（§6 实测 EINVAL）；4.18/5.4 档全部黄格落不了地，仓库仅有
   `bpf/lsm_file_perf.bpf.c`（`-DUSE_PERF_BUFFER`）先例可复用。
2. **兼容矩阵实测欠账**：RHEL8 4.18 的 BTF backport 与 lsm_kprobe 加载待实测（清单 #1/#3 的 4.18 半）；
   5.10/6.x 真机未跑过；`module:module_load` 在 5.x 的实际上报字段未验证（清单 #5）。
3. **Syslog 第二通道**：W7 进行中，顺延 W8 收口（M7-3 三通道之一）。
4. **G9 降级实现**：`lsm/inode_setattr` 钩子（ATTR_SIZE 过滤，约 30 行 BPF + 用户态映射），
   W7 D2 决策排 W10 后。
5. **RSS 瘦身**：降监视项（W6 实测 138.2MB 无增长，红线 150MB，超 145MB 再立项）。

## 4. W8–W14 逐周计划（每周一句话）

| 周 | 一句话计划 |
|---|---|
| W8 | perf 降级版攻坚第一段：priv_watch/net_watch/proc_watch 的 perf buffer 通道开发（复用 lsm_file_perf 先例），开发机编译 + 加载自测通过；Syslog 通道收口（W7 顺延）。 |
| W9 | 降级链路用户态接线：内核版本探测自动切换 perf 通道、事件解析与 ringbuf 路径对齐，本机双通道 A/B 冒烟一致。 |
| W10 | 5.4 真机（Ubuntu 20.04 VM）全量实测 perf 降级链路：run_all.sh 30 用例在降级模式两轮跑通，矩阵 5.4 黄格转实测结论。 |
| W11 | RHEL8 4.18 环境准备 + 实测：`/sys/kernel/btf/vmlinux` 存在性、lsm_kprobe 加载、perf 通道出事件，4.18 档定性（支持 or 降级为"设计目标"）；插缝实现 G9 inode_setattr 降级。 |
| W12 | 5.10 与 6.x 各一档真机实测 + `module:module_load` 字段对账，矩阵四档全部转实测结论、无"待实测"残留。 |
| W13 | v1.0 全量回归周：30 用例 ×2 轮检出率 100%、CIS 40 项无回归、性能四指标冒烟 + RSS 红线复核、unit 全绿。 |
| W14 | 出口口径预审与缓冲：README 支持矩阵、changelog、发布材料草稿，perf 降级与实测遗留问题收口，进入 W15–W18 缓冲段。 |

## 5. 风险对位（方案 A 固有风险，原文照录口径）

- perf 降级版是内核类工作，历史上此类工作持续被低估（W3 性能攻坚吃掉 W4 前两天、W6 CIS 引擎挤占规则包），
  故排 W8–W10 前置，缓冲留在后段；
- 4.18 档依赖 RHEL8 BTF backport 实测，若小版本无 BTF 则 4.18 档整体降级为"设计目标、不支持"，
  范围被动收缩（W11 出定性结论）；
- 传导路径：perf 降级延期 → 兼容实测顺延 → 出口前突击——W8–W10 任一周滑期即触发 W14 缓冲。
