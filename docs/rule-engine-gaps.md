# 规则引擎能力缺口记录（W6 D1 起）

> 用途：规则编写中发现"condition 表达不了 / 写了不生效"时登记于此，**不现场改引擎**。
> 每条含：缺口、影响、本次规则的退化方案。

## G1 无进程 cmdline/argv（schema 已知边界，docs/event-schema-v1.md §4）

- 影响：`exec-reverse-shell-bash` 的 `bash -i` 交互标志、`exec-reverse-shell-interpreter` 的 python/perl `socket+pty` 命令行组合特征、`cred-clear-history` 的 `history -c` 内建命令，均不可表达。
- 退化方案：规则 1 用"shell 的祖先链含解释器/网络工具"近似；规则 2 只覆盖 exe 可识别的双用途工具（nc/socat 家族），python/perl 放弃；规则 8 只覆盖文件层面的 history 清空/删除。
- v2 方向：exec 事件采集 cmdline（受内核截断限制，建议前 256 字节）。

## G2 无 fd/socket 关联信息

- 影响：Falco 式 `fd.type=socket and proc.name=bash`（stdin/stdout 重定向到 socket 的交互式 shell 判定）不可表达。
- 退化方案：同 G1，祖先链启发式。
- v2 方向：exec 事件富化 stdin/stdout fd 类型，或与 network 事件做跨事件关联（G5）。

## G3 network/dns/priv/ns 事件未接入规则引擎

- **已修复（2026-10-09）**：`route_event` 补齐四类事件的 EventView 构造与求值调用（`eval_rules_on_net_event` / `eval_rules_on_priv_event`，复用渲染 JSON 字段，语义与 file/process 一致）；根因防御同步落地——condition 中 `event_type` 的 `=`/`in` 字面值加载期对照已知事件类型表校验，表外直接报错（`condition_parser.cpp`），未知字段此前已报错，"写了不触发不报错"路径全部封死。验证：priv.ptrace / ns.unshare / network.connect / network.dns 各一条规则手动触发命中并落库。
- 原现状：`route_event`（src/baseline/monitor.cpp:1412-1486）只对 CAT_FILE 与 CAT_PROCESS(exec) 调用 DSL 求值；`rule_engine.cpp` 虽有 net_*/dns_*/priv_* 字段解析与事件类型表，但无接线。**写 `event_type = network.connect` 的规则不会触发，也不报错**。
- 原影响：本次"shell 直接发起 TCP 外连（/dev/tcp 反弹特征）"的最强信号不可用。
- 原退化方案：反弹 shell 检测全部走 process.exec 路径。

## G4 无 endswith/正则/glob

- 影响：`exec-suspicious-tmp-binary` 的"无扩展名"只能用 `not process.exe contains .` 近似——路径任一段含 `.`（如 `/tmp/.hidden`、`/tmp/v1.2/x`）即豁免；隐藏文件类落地（`/dev/shm/.x`）漏报。
- v2 方向：加 `endswith` 操作符或 glob 字面量。

## G5 无跨事件关联（v1 非目标，docs/rule-dsl-v1.md §7 已声明）

- 影响："exec 后 N 秒内出现 connect"类时序规则不可表达；本次反弹 shell 规则的单事件判定因此偏宽。
- v2 方向：状态机 + 时间窗，与 M5-3 聚合降噪协同。

## G6 file 事件仅覆盖 config monitor.path 注册的 inode

- **已部分修复（2026-10-12，W7 D1）**：DSL 规则 condition 中 `file.path` 的 `=`/`in` 字面量路径在加载/热加载时自动登记进内核 monitor_actions map（`src/detect/rule_loader.cpp` `ExtractFilePathRefs` + `src/baseline/monitor.cpp` `dsl_sync_registrations`），未基线文件规则开箱即触发；引用计数反登记，config/基线覆盖的 inode 不误删。残余边界：startswith/contains 前缀语义仍依赖既有登记（下述 v2 方向）；与既有条目共享 inode 时沿用其 events_mask。
- 原现状：BPF 侧 `monitor_actions` map 查不到 inode 直接 return（bpf/lsm_file.bpf.c:37-40 等）；用户态只注册 config `rules:` 与 baseline 库内文件（src/baseline/monitor.cpp:774-861）。**DSL 规则单独写 `file.path = X` 而 config 未注册 X 时永远无事件**。文件删除重建后 inode 变化，需 SIGHUP 热加载重新注册。
- 影响：`cred-tamper-authorized-keys`、`cred-clear-history` 面向"任意用户家目录"的路径无法一规则全覆盖，只能逐文件注册。
- 退化方案：测试配置显式注册测试路径；生产部署按资产清单批量注册关键用户的 history/authorized_keys。
- v2 方向：支持目录前缀注册（path prefix → BPF map 前缀匹配或用户态过滤全量事件）。

## G7 无路径变量/宏（DSL §4 已声明不支持宏）

- 影响：`cred-write-passwd` 的"真实路径 + 测试替身路径"只能把替身路径硬编码进 condition 列表。
- 本次选型：测试替身路径 `/tmp/bg-attack-cases/passwd-copy` 写入规则 condition（bind-mount 方案因 G6 的 inode 注册机制失效——bind 后目标 inode 不是已注册 inode，无事件）。

## G8 单事件只报首个匹配规则（无多命中）

- **决策记录（2026-10-12，W7 D2）：不改，单命中定为显式设计**，约定已写入 `docs/rule-dsl-v1.md` §8（单命中 + 规则命中域互斥约定）。
  - 统计数据：`RuleEngine::Evaluate` 临时改收集模式（只统计不改语义，跑完即还原）跑 22 用例 × 2 轮——242 个命中事件中多命中 54 个（22.3%，hits=2×14 / hits=3×2 / hits=8×26 / hits=10×12）。构成：38 个为 perf-100 压测规则的人为同构重叠（benchmark 规则本就写成一个路径族全覆盖，无实际意义）；14 个为 core 遮蔽 examples（目录加载序 core < examples 即预期优先级）；core-vs-core 仅 2 事件（Exec Reverse Shell Under Interpreter 与 Exec Webspawner Shell 同族重叠），告警不丢检测结论、只丢规则归属粒度。
  - 结论：多命中率 >20% 但无实际遮蔽危害，"改全命中"的告警量翻倍收益不抵成本；若未来出现真实的 core 规则互遮需求，再按 v2 方向实施。
- 现状：`RuleEngine::Evaluate` 返回单个 MatchResult（src/detect/rule_engine.cpp:621），按桶内加载顺序（目录路径排序，core < examples < perf-100 < storm）取第一条命中规则即停；`eval_rules_on_exec_event` 只发送这一条告警（src/baseline/monitor.cpp:1394-1397）。
- 原影响：条件重叠的规则互相遮蔽——先加载者吃掉事件，后加载者静默无告警（W6 D1 实测：规则 1 的祖先列表含 node 时，`exec-webspawner-shell` 全量被遮蔽 0 告警）。
- 本次应对：core 内 8 条规则的命中域做了互斥设计（规则 1 去掉 node，webshell 场景让给规则 4）；编写重叠规则时必须检查加载顺序与遮蔽关系。
- v2 方向：Evaluate 返回全部命中列表，告警侧按规则去重/节流。

## G9 file.write 只对真实 write(2) 字节产生（kernel 7.0 实测）

- **决策记录（2026-10-12，W7 D2）：三方案评估后选降级，排 W10 后**。
  - A（验证现有钩子是否已覆盖，可能零代码）：实测 kernel 7.0.0-38——对已注册 inode 的目标文件分别执行 `truncate -s 0`、`: > F`（O_TRUNC 不写数据）、`cp /dev/null F`，三者在 events.db **均零 file 事件**（对照组 `echo >> F` 正常产生 file.write，mask=2）。`lsm/file_permission` 在 open(O_TRUNC) 与 truncate(2) 路径均不触发，A 不可行。
  - B（open flags O_TRUNC 检测）：不存在 open 事件，事件结构无 flags 字段（bpf/event.h），需新增钩子 + 新字段，成本等同内核侧改动；且"open 写意图"语义比"真实写字节"宽得多（编辑器/shell 打开即报），噪声风险大，不取。
  - C（新增 `lsm/inode_setattr` 钩子过滤 ATTR_SIZE）：唯一能精确覆盖 truncate/ftruncate/O_TRUNC 三路径的点（三者都走 notify_change 的 ATTR_SIZE），估约 30 行 BPF + 用户态事件映射；属内核侧改动，按 W7 D2 约束记降级，排 W10 后评估。
- 现状：只 open(O_TRUNC) 不写数据（`cp /dev/null F`、空输入 `tee F`）、或纯 `truncate(2)` 系统调用（`truncate -s 0`）都不产生 file.write 事件；有实际写入才上报。
- 影响：`cred-clear-history` 对"打开即截断但不写"的清空手法不可见；攻击用例不能用 truncate/cp-null 触发（case-14 改用 `dd conv=notrunc`）。

## G10 ns.names[] 元素命名与 schema 文档不一致

- **已修复（2026-10-12，W7 D2）**：选型"保留渲染现状（去 `CLONE_` 前缀），文档拉齐"——改动面最小，不破坏已验证的 ns.flags 数值路径与落库历史数据。三处同步：`docs/event-schema-v1.md` §2.5、`docs/rule-dsl-v1.md` §3 示例改为无前缀口径（NEWNS/NEWUSER）；`tests/unit/test_rule_dsl.cpp` RDSL-015 期望同步。回归：case-18（priv-unshare-userns）通过。
- 原现状：schema（docs/event-schema-v1.md §2）与 DSL 文档示例写作 `["CLONE_NEWNS"]`，实际渲染（src/baseline/monitor_privilege.cpp `decode_ns_flags`）输出去 `CLONE_` 前缀的名字（`NEWNS` / `NEWUSER` / `NEWNET` …）。写 `ns.names[] = CLONE_NEWUSER` 永不触发。

## G11 file.new_mode 渲染掩掉 setuid/setgid/sticky 高位

- 现状：EventView 构造与落库 JSON 均做 `mode_to_string(new_mode & 0777)`（src/baseline/monitor.cpp:1324、1184），04755 渲染为 "0755"、04644 渲染为 "0644"。
- 影响：`priv-suid-file-create` 无法直接判定 SUID 位——`chmod 4755` 与 `chmod 755` 不可区分（混报），`chmod u+s` 作用于 0644 文件时渲染为 "0644" 完全不可见（漏报）。
- 退化方案：规则以 `file.new_mode = 0755` + exe 白名单近似，fpr_note 告知告警后须 stat 复核真实 mode。
- v2 方向：渲染保留完整 mode（`& 07777`，4 位八进制字符串），历史数据格式兼容在 W7 一并评估。

## G12 无位运算操作符（ns.flags 组合位不可表达）

- 现状：比较操作符仅 `= != in contains startswith`，无 `&`/位测试。
- 影响：`priv-unshare-userns` 要表达"flags 含 CLONE_NEWUSER 位"只能枚举具体数值（当前枚举纯 NEWUSER=268435456 与 NEWUSER|NEWNS=268566528），`unshare -U -m -p` 等其它组合漏报。
- 退化方案：in 列表枚举最常见组合。
- v2 方向：加 `bitand`/`has_flag` 类操作符（Falco 语义：`ns.flags & 268435456 != 0`）。

## G13 exec 事件无环境变量采集

- 现状：`process.exec` 负载只有 process.* 公共字段（docs/event-schema-v1.md §2.2/§4），无 env。
- 影响：`persist-ld-preload` 的"LD_PRELOAD/LD_AUDIT 环境变量启动进程"一半不可表达，只覆盖写 /etc/ld.so.preload 文件面。
- 退化方案：规则仅文件面，env 注入依赖其它行为信号（可疑 .so 落盘 + exec 时序人工研判）。
- v2 方向：exec 事件选择性采集敏感 env（LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH，非全量，防噪声与隐私问题）。

## G14 priv.module_load 事件无模块路径/来源字段

- 现状：`priv.module_load` 只有 `priv.name`（模块名，tracepoint module:module_load），无 .ko 文件路径。
- 影响：`priv-kernel-module-load` 无法区分"同名合法模块（/lib/modules 下）"与"伪装同名 rootkit（/tmp/x.ko）"，只能靠模块名白名单降噪。
- v2 方向：内核侧补 finit_module 的 fd→路径解析或 kernel_read_file(READING_MODULE) 路径字段。

## G15 file.new_mode 渲染为 rwx 符号串，与 schema 文档的八进制口径不符

- **已修复（2026-10-12，W7 D2，改文档不改代码）**：选型理由——rwx 符号串可读性更好，且 W6 D6 起规则（priv-suid-file-create 等）与单测（test_utils UTL-003~005、TESTCASES.md）均已按 rwx 字面量编写验证，改代码为八进制需连带改规则与历史数据；改文档零风险。三处同步：`docs/event-schema-v1.md` §2.1、`docs/rule-dsl-v1.md` §3 改为 rwx 串口径，并补注 SUID 高位被 &0777 掩掉、无 rws 形式（G11 未决，SUID 判定仍不可表达）；单测本就按 rwx 期望，无需改。回归：case-15（priv-suid-file-create）通过。
- 原现状：schema（docs/event-schema-v1.md §2.1）与 DSL 文档（docs/rule-dsl-v1.md §3）写 `file.new_mode 如 "0644"`，实际渲染（src/common/utils.cpp `mode_to_string`）输出 9 字符 rwx 符号串（如 "rwxr-xr-x"）。写 `file.new_mode = 0755` 永不触发（W6 D2 case-15 首轮实测踩出）。
- 原影响：mode 类条件必须用 rwx 字面量（`file.new_mode = rwxr-xr-x`）；与 G11 掩码叠加后，SUID 判定可用字面量只剩"4755/0755→rwxr-xr-x"一种近似。

## G16 多 monitor 实例并存时告警互相串扰（运行态，非 DSL 表达力）

- **已修复（2026-10-12，W7 D1）**：`do_monitor` 入口加 flock 单实例锁（`src/common/instance_lock.cpp`，锁文件 `/var/run/baseline-guard-monitor.lock`），探针加载前获取；第二实例报错退出（提示含持锁 pid + 锁文件路径，exit 1）；正常退出与 kill -9 均由内核自动释放。
- 原现状：多个 baseline-guard monitor 并存时各自加载规则快照、各自维护节流状态、消费同一批内核事件并落同一系统告警库（/var/lib/baseline-guard/baseline.db）。残留旧实例（规则集不同）会与新实例对同一事件产出不同 rule_id 的告警（W6 D2 实测：残留实例无 persist-container-docker-exec，命中落到示例规则 dsl.docker_cli_executed_inside_container，case-22 出现"同一动作有时命中 core 有时命中 examples"的假象）。
- 本次应对：run_all.sh 启动前清理残留 monitor 进程；文档记录该现象以免误判为规则/引擎不确定性。
- v2 方向：monitor 启动时检测同 config 的存活实例（pidfile/flock 互斥）。

## G17 规则加载失败静默降级为空引擎（W6 D3 事故，加载器可靠性）

- **已修复（2026-10-12，W7 D1）**：启动路径 fail-fast——任一规则文件加载/编译失败、或 enabled 但加载 0 条规则，`do_monitor` 直接报错拒绝启动（err 含文件名+行号+原因）；CIS 定义文件移出 `rules/` 递归范围（`rules/cis/` → `cis/`，cis_main 默认路径同步）。热加载路径语义不变（失败保留旧快照）。回归纪律见 `CONTRIBUTING.md`。
- 原现状：`rules/cis/cis-baseline-v1.yaml`（CIS 检查项定义，非 DSL 规则）被 rules_dir 递归加载解析失败，`LoadRulesDir` 整体 false 后 monitor 仅 warn 继续运行（rule_loader.cpp:136 → monitor.cpp:1815），DSL 告警空窗 2 天。

## G18 规则内文件路径无法登记时加载期无提示（加载警告缺口）

- **已修复（2026-10-12，W7 D1）**：随 G6 登记流程落地——路径不存在 / 非绝对路径 / 含通配符三类逐条 warn（格式：规则ID + 路径 + 原因 + "该文件条件不生效"降级说明），map 写失败（容量满）同款 warn；不阻断其余规则加载。语义边界：规则文件本身解析失败 = G17 fail-fast；规则内路径登记失败 = 本项 warn 降级。

## G19 无 cmdline 使"同 exe 不同意图"的工具类规则只能退化（G1 的影响扩展登记）

- 现状：同 G1（exec 无 cmdline/argv），W7 D3 写防御规避/挖矿规则时影响集中爆发，单独登记以挂 v2 草案。
- 影响（W7 D3 实测退化）：`evasion-stop-audit-service` 的 systemctl **动作与目标**（stop/disable + auditd/rsyslog）不可判定，退化为 systemctl 执行即报（priority 降 medium，status/restart 全命中）；`evasion-chattr-immutable` 的 **+i/-i** 不可区分；`evasion-kill-security-tool` 的 **pkill 目标进程名**不可判定，退化为 kill 家族执行即报；`mining-binary-exec` 的 **--donate-level / stratum+tcp://** 命令行特征不可表达，随机改名矿机漏报。
- 退化方案：exe 命中 + fpr_note 声明噪声（**不能**用祖先链豁免 systemd 做降噪——pid 1 恒在 8 层祖先链内，豁免即全量静默，W7 D3 首轮回归实测 case-28/30 零告警踩出）；检出缺口靠 shm 执行/矿池端口/DNS 三条单因子规则互补。
- v2 草案（cmdline 采集落地后改写）：
  - stop-audit：`process.exe in (systemctl 路径) and process.cmdline contains (stop, disable) and process.cmdline contains (auditd, rsyslog, audit)`；
  - chattr：`process.exe = chattr 路径 and process.cmdline contains +i`；
  - kill-security-tool：`process.exe in (pkill, killall) and process.cmdline contains (falco, edr, baseline-guard, osquery, auditd)`；
  - mining-binary：`process.cmdline contains (--donate-level, stratum+tcp, stratum+ssl)`（与 exe 名 or 关系）。

## G21 exe 富化解析符号链接真实路径，argv[0] 双行为二进制按 exe 不可区分

- 现状：exec 事件的 `process.exe` 富化为可执行文件真实路径——`/usr/bin/pkill` 是指向 `pgrep` 的符号链接，pkill 执行时 exe 渲染为 `/usr/bin/pgrep`（W7 D3 case-30 实测：condition 写 pkill 路径零命中，events.db 中 comm=pkill、exe=/usr/bin/pgrep）。busybox/toybox 家族（/bin/ls → busybox）同款。
- 影响：按"调用名"区分行为的工具（pkill vs pgrep 只读查询、killall vs pidof），按 exe 写规则要么漏报（写 pkill 路径永不命中）、要么混报（写 pgrep 路径把只读查询也报进来）。
- 退化方案：`evasion-kill-security-tool` 改用 `process.comm in (pkill, killall)` 判定调用名（comm 即 argv[0] 前 15 字符），可伪造的权衡写入 fpr_note。
- v2 方向：exec 事件同时携带 exe 原始路径（未解析符号链接）或 argv[0]。

## G20 无 CIDR/网段比较（IP 白名单只能逐字面量枚举）

- 现状：`network.sip/dip` 为点分文本 string，比较仅 `=`/`!=`/`in`/`contains`/`startswith`；无 CIDR 匹配（如 `network.dip in 10.0.0.0/8`）。
- 影响：`mining-pool-port-connect` 想"排除内网/回环"只能 `and not network.dip in (127.0.0.1, ...)` 逐 IP 枚举，回环段 127.0.0.0/8 枚举世不可行；最终选型"端口匹配不强制外网 IP"（理由见该规则 desc：回环白名单会放行本地代理跳板挖矿路径）。
- v2 方向：加 `cidr` 操作符或 startswith 按段近似（`network.dip startswith 10.` 已可表达但语义粗糙，点分文本前缀与子网不对齐）。
