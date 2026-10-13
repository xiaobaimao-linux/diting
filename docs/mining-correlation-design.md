# 挖矿检测跨事件关联设计（v2 排期，本文档只做设计不实现）

> 背景：W7 D3 落地 4 条单事件挖矿规则（rules/core/mining-ta0040.yaml）。
> 单事件判定的固有短板是"单因子误报/漏报"——任一信号单独出现都可能双义。
> 本文档记录三因子关联检测的设计思路，依赖 DSL v2 能力，**不在 v1 实现**
> （v1 非目标：跨事件关联，docs/rule-dsl-v1.md §7-1；缺口 G5）。

## 1. 目标检测式（三因子）

挖矿进程的判定置信度来自信号组合，而非任一单信号：

```
confidence = f(陌生二进制执行, 矿池外联/DNS, 资源异常)
```

- **因子 A：陌生/可疑二进制执行**——exe 不在资产基线（非系统路径、无包管理来源），
  或落地于 /tmp、/dev/shm、家目录隐藏路径。v1 已覆盖最强特例（mining-binary-exec、
  mining-shm-exec、exec-suspicious-tmp-binary）。
- **因子 B：矿池外联**——dport ∈ stratum 端口集 或 DNS 命中矿池域名特征。
  v1 已覆盖（mining-pool-port-connect、mining-pool-dns）。
- **因子 C：资源异常**——进程级持续高 CPU（矿机满载特征）、可选 GPU 占用
  （本项目已有 gpu_collector，数据源现成）。

单因子告警（v1 现状）= 低置信线索；A∩B 或 B∩C 同时成立 = 高置信挖矿，可直接升级 critical。

## 2. 关联语义设计（v2 DSL 草案）

```yaml
- correlation: Mining Multi Factor
  window: 10m                     # 滑动时间窗
  group_by: process.pid           # 关联键：同进程（DNS/连接/exe 同一发起者）
  factors:
    - rule: Mining Binary Exec    # 引用 v1 单事件规则命中
    - rule: Mining Pool Port Connect
    - metric: process.cpu_percent > 80 sustained 5m   # 指标型因子（非规则）
  require: any 2 of 3             # 三取二即升级
  priority: critical
  attack: [T1496, TA0040]
```

要点：

1. **关联键 group_by**：首选 pid（exec/connect/dns 事件都带）；pid 复用风险用
   "exec 事件重置该 pid 的因子状态"兜底。退而求其次按 uid + 时间窗。
2. **时间窗**：矿机连接矿池是长连接 + 周期任务，10 分钟窗足够让 A/B/C 同框；
   窗口状态落内存即可，monitor 重启丢失可接受（矿机是持续行为，下个窗口再命中）。
3. **三取二而非三取三**：CPU 受限环境（cgroup limit、低优先挖矿）因子 C 可能缺失；
   改名矿机缺因子 A；三取二保检出。
4. **状态机复用**：与 G5 的"exec 后 N 秒内 connect"通用时序关联同一套窗口状态机，
   挖矿关联是它的一个 rule 实例，不做专用实现。
5. **降噪协同**：关联告警与 M5-3 聚合降噪配合——单因子告警降级为 context（不通知、
   只落库），关联命中才出 critical 通知，从根上解决 v1 单因子规则的噪声。

## 3. 数据来源现状盘点

| 因子 | 数据源 | 现状 |
|---|---|---|
| A 陌生二进制 | process.exec 事件 + 资产基线（asset 模块已有进程/软件清单） | 事件就绪；"陌生"判定需基线比对，v2 工程量最大的一项 |
| B 矿池外联 | network.connect / network.dns 事件 | 就绪（G3 已修复，W7 D3 规则已验证命中落库） |
| C 资源异常 | 进程 CPU 采样（/proc 轮询）+ gpu_collector | GPU 侧就绪；进程级 CPU 持续采样需新增采集器（当前只有事件流，无指标流） |

## 4. 排期建议

1. v2 前置：cmdline 采集（G19，提升因子 A 精度：stratum+tcp 特征直接判死）。
2. 窗口状态机 + `correlation` 语法（G5 通用能力）。
3. 进程 CPU 指标流（因子 C 采集器）。
4. 挖矿关联规则作为 correlation 首用例上线，v1 四条单因子规则保留作 context 供给。
