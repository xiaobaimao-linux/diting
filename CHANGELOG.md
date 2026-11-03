# Changelog

本项目所有面向使用者的变更记录于此。格式按版本分段，最新版本在最上方。

## v1.0.0-rc1（2026-11-03）

diting 首个发布候选。v1.0 = 方案 B+C 混合：eBPF 主机安全遥测 + 文件完整性监控（FIM）+ 规则引擎检测 + CIS 基线 + AI 安全专项。本版本为正式发布前的最后一道闸。

### Highlights

- **eBPF 遥测 + FIM**：五类内核级遥测（文件、进程生命周期 exec/fork/exit、网络 connect/accept/bind、DNS、权限 setuid/capset/ptrace/module_load），CO-RE 单二进制跨内核；文件完整性基线快照 + 实时比对（新增/删除/内容/权限/属主变更）。
- **规则引擎（DSL，30 条规则）**：声明式 condition DSL，core 规则包覆盖执行（TA0002）、持久化（TA0003）、防御规避（TA0005）、提权（TA0004）、凭据访问（TA0006）、挖矿（TA0040）六大类。
- **36 个攻击用例自检**：`tests/attack-cases/` 内置攻击模拟用例库，一键回归验证检出能力。
- **CIS 基线 40 项**：离线检查器（`cis check` / `cis report`），三态判定（pass/fail/na），等保 2.0 映射 + 每项附修复命令，支持 HTML/JSON 报告导出。
- **告警体系**：四级 severity（critical/high/medium/low）；webhook + syslog（RFC 5424）双外发通道；静默窗口、风暴聚合降噪（外发侧窗口合并，落库逐条不变）、分级路由。
- **AI 安全专项**：AI 资产识别（GPU 采集 + 模型文件发现 + AI 工作负载进程识别）；AI 告警升级（升一级封顶 critical，落库可审计）；AI 专项规则包 6 条（配套用例 case-31~36）。

### 稳定性证据

- 云端双机（Ubuntu 24.04/6.8 与 22.04/5.15）**连续 133.2 小时零重启**（systemd NRestarts=0），全程五类丢失计数（reserve_failed 四探针、bus.queue_full 高低水位、backpressure_drop、batch_overflow、store_failed）**全零**。
- pushed−stored 对账差值随收尾收敛（A 0.61% / B 4.93%，且 store_failed=0）——为在途批次/去重口径的正常暂差，**无事件丢失**。
- 资源占用：RSS 峰值 A 机 144.0MB / B 机 133.7MB（红线 150MB）；CPU 稳态均值 A 0.88% / B 0.51%。详见 `docs/soak-72h-report.md`。
- 全新安装矩阵双机 72/72 用例全绿、零 flake（`docs/install-matrix-w10.md`）。

### 安装与分发

- 预编译 tarball 秒级安装（实测 0~4s），双版本：`ubuntu-22.04` 与 `ubuntu-24.04`（x86_64），容器内构建保证 ABI 对口。
- libbpf 1.4.5 vendored 静态链接，运行时零外部 libbpf 依赖（唯一系统依赖：libelf/zlib，apt 常见包）。
- install.sh 含前置检测（内核版本/BTF/依赖），预编译优先、源码编译兜底并行构建。

### 竞态问题根治

- **case-06（G24 关联）**：容器归属在**事件时刻内核侧捕获**（cgroup 叶子名随事件携带），不再依赖用户态事后读 /proc，消除短寿容器归属错判。
- **case-07（G24 根治）**：exec 事件 exe 富化与进程原地再 exec 的用户态竞态（/proc 读到新映像导致 exe 名单类规则间歇漏报）已根治。

### Known limitations（如实列示）

1. **G9 truncate 不可见**：`file.write` 事件只对真实 write(2) 字节产生；纯 `truncate(2)` / `cp /dev/null F`（O_TRUNC 不写数据）不产生事件。修复方案（`lsm/inode_setattr` 钩子）已定，排 v1.0 之后。
2. **G20 无 CIDR 匹配**：`network.sip/dip` 只支持字面量 `=`/`!=`/`in`/`contains`/`startswith`，无网段比较；IP 白名单需逐字面量枚举。
3. **5.15 内核 chown 降级**：5.15 上 `path_chown` LSM 钩子的 kuid_t/kgid_t 参数触 verifier 拒绝，自动降级为禁载 chown 钩子（CHOWN 实时检测缺失），其余探针不受影响；日志有显式降级提示。
4. **cmdline 256B 截断**：exec 事件命令行采集前 255 字节（内存预算决策，超长命令行尾部不可见）。
5. **其余开放缺口 14 项**（G4 endswith/glob、G5 跨事件关联、G12 位运算等 DSL 表达力边界）：见 `docs/rule-engine-gaps.md`；G24/G25 已关闭。

### 平台口径

- 支持：Ubuntu 22.04（kernel 5.15）与 Ubuntu 24.04（kernel 6.8），x86_64。
- 最低要求：kernel ≥ 5.8（BTF + LSM BPF），需 root 运行；5.4 档走 kprobe/perf buffer 降级链路（遥测能力子集，详见 `docs/kernel-compat-matrix.md`）。
