# 谛听（Diting）品牌指南

> 本页为对外品牌使用规范。媒体、社区与贡献者引用本项目名称与标识时，请以本页为准。
> 前身：diting（2026-10 更名为 diting，仓库历史与 Star 完整保留）。

## 1. 名称

| 场景 | 写法 |
| --- | --- |
| 中文正式 | 谛听 |
| 英文 / 代码 / 仓库 | diting（全小写） |
| 标题中首次出现 | 谛听（Diting） |
| 组件命名 | `diting-sensor`（探针）、`diting-console`（管理中心） |

**品牌故事**：谛听是地藏菩萨座下神兽，善听万物、辨真伪，《西游记》中唯它能分辨真假美猴王——正如 eBPF 探针在内核态"听"见一切动静，并用内核视图与 `/proc` 视图的交叉比对拆穿 Rootkit 的伪装。

*Diting is named after the mythical creature that hears everything and tells truth from disguise.*

## 2. 一句话定位

> 谛听 Diting：给云服务器和 AI 集群装上内核级的耳朵——一个 eBPF 安全探针，听得见进程、文件、GPU 和模型文件的动静，辨得出真假，轻到可以忽略。

*An eBPF-based host security sensor for cloud servers and AI clusters — it watches processes, files, GPUs and model files, and stays lightweight.*

差异化支柱：① AI 负载一等公民（GPU / 模型文件 / 推理服务与进程、文件、网络并列为核心监控对象）；② 内核级 + 轻量（eBPF 事件驱动，实测开销公开）；③ 合规即输出（等保 2.0 / CIS / MITRE ATT&CK 条款映射）。

## 3. Logo

唯一标识：DT 字母组合（衬线风格 monogram，D 的负形中含一滴水——"谛听滴水之声"）。

| 版本 | 文件 | 用途 |
| --- | --- | --- |
| 标准版 | `docs/assets/logo-dt.png`（墨绿，透明底） | 浅色底：文档、README、头像、文章配图 |
| 白色变体 | `docs/assets/logo-dt-white.png` | 深色底：幻灯片、深色模式 |

使用规范：

- 最小使用尺寸 32px
- 浅色底用标准版，深色底一律用白色变体
- 请勿拉伸、改色、加阴影或置于低对比度背景上

## 4. 色值

| 色 | 值 | 用途 |
| --- | --- | --- |
| 谛听墨绿 | `#092623` | 主色：Logo、标题、强调 |
| 深底 | `#181820` | 深色背景（此底上 Logo 用白色变体） |
| 浅底 | `#F5F5F5` | 浅色背景 |

## 5. 术语说明

- 本项目的主机端组件称为**探针（Sensor）**。它工作在主机与内核层面，观测进程、文件、网络与 GPU 行为；不提供 prompt 内容审计或大模型输出检测——那属于网关类产品。引用时请使用"谛听探针"或 "Diting Sensor"，以避免与 AI Agent（智能体应用）混淆。
- 文档与界面中的性能与检测数据均为实测值，测量方法见每周开发日志与测试记录。
- 合规相关输出（等保 / CIS 核查报告）为测评辅助证据，不构成法定测评结论。
- 内核态阻断能力默认关闭，需显式开启并先经 dry-run 观察期；引用相关能力时请保留此前提。

## 6. 授权

- 代码：Apache License 2.0
- 名称与 Logo：保留所有权利。在指代本项目、撰写报道或教程时可自由使用；不得用于暗示官方背书或用于衍生商业产品的命名。

---

*Diting 是单人维护的开源项目。品牌相关问题请开 Discussion 或 Issue。*
