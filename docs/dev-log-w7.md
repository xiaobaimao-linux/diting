# W7 开发日志：每个零件都合格，拼起来漏

> 状态：W7 收官。集成缺口三连终结——加载器 fail-fast（G17）、DSL 文件规则 inode 自动登记（G6/G18）、flock 单实例锁（G16）；core 规则包补到 24 条（挖矿/防御规避 8 条），攻击用例库 22→30 并踩出 3 个真 bug；缺口登记到 G21。

## 本周做了什么

**1. 加载器 fail-fast：静默空跑比报错贵得多。** 上周 D5 回归的 5/22 不是规则问题：CIS 定义文件混进 rules/ 被递归加载，解析失败后 LoadRulesDir 整体返回 false，monitor 只打一行 warn 继续跑——DSL 引擎空转两天，单测全绿、冒烟正常、性能指标漂亮，只有端到端用例兜得住。本周第一刀就砍在这里：任一规则文件解析/编译失败、或引擎 enabled 却加载 0 条规则，直接拒绝启动，错误带文件名和行号；CIS 定义挪出 rules/ 递归范围。热加载路径刻意不动——运行中改错配置保留旧快照，可用性优先；启动是"建立信任"的时刻，必须 fail-fast。配套立了提交纪律（CONTRIBUTING.md）：动 rules/ 或加载器代码，提交前必须跑 30 用例两轮回归，检出率低于 90% 红线禁止合入。

**2. DSL 文件规则自动登记 inode：开箱即坏与开箱即用之间只差一个决策。** G6 的老问题：DSL 规则写 file.path = X 而 config 没注册 X，内核 monitor_actions map 查不到 inode 直接丢事件——规则永远静默不触发。W6 校准把"自动注册 vs 加载期警告"列为待拍板决策点，本周拍板自动注册：加载时从 condition 树抽出 file.path 的 =/in 字面量（ExtractFilePathRefs），自动登记进内核 map，引用计数反登记、不碰 config 和基线已占的 inode；路径不存在、相对路径、含通配符三类逐条 warn 降级（G18），不拖累同文件其它规则。语义边界划清楚了：规则文件本身解析失败 = G17 fail-fast；规则内单个路径登记失败 = warn 降级。用户写一条 file 规则就能收到告警，不用再先跑基线。

**3. 单实例锁：终结"引擎不确定性"假象。** W6 case-22 出现过"同一动作有时命中 core 规则、有时命中 examples 规则"的怪象，一度怀疑引擎求值不确定——真凶是历史会话残留的 monitor：两个实例消费同一批内核事件、各自节流、落同一个告警库。本周 flock 单实例锁落地（/var/run/diting-monitor.lock，探针加载前获取），第二实例带持锁 pid 报错退出；fd 进程级持有，正常退出和 kill -9 都由内核自动释放，不留死锁残局。run_all.sh 里"清残留"的防御脚本退役——机制代替纪律。

**4. 规则包补齐口径：挖矿 + 防御规避 8 条。** mining-ta0040 四条（矿池端口/DNS/矿机名/shm 执行）、defense-evasion-ta0005 四条（清安全日志/停审计服务/chattr 锁文件/杀安全工具），core 到 24 条，W6 欠的 20+ 口径还清。cmdline 不可见（G1）的账在这批规则上集中爆发，单独登记 G19：systemctl 的动作与目标、chattr 的 +i/-i、pkill 的目标进程全都判不了，三条规则退化为 exe/comm 命中即报，噪声权衡写进 fpr_note，v2 草案（cmdline contains）一并存档。命中域互斥同步调整：/dev/shm 从 tmp 规则移交 mining-shm-exec 独占，case-26 双向断言（shm 规则 ×≥1 且 tmp 规则 ×0）。三因子关联挖矿设计（陌生 exe + 矿池外联 + 资源异常，三取二升 critical）定稿排 v2，不在 v1 实现。

**5. 用例库 22→30，踩出 3 个真 bug。** 这是本周最值钱的产出，细节见下节。回归最终 60/60，unit 110/110。另：syslog 外发第二通道落地（INotifier 的第二个实现，webhook 之外的标准运维通道，dispatcher 的重试与失败计数直接复用）；RSS 瘦身专项按 W6 决议降级为复核——W6 实测 138.2MB 无增长、DSL 规则 3→119 条仅占 ~0.4MB，瘦身的投入产出比不成立，本周以红线复核代替，数据见 W7 S5 报告。

## 用例踩出的三个真 bug

三个 bug 没有一个是引擎代码写错了——错的是我们对系统事实的假设。

**pid1 豁免等于全量静默。** 防御规避规则初版想降噪，写了 `not process.ancestors[].comm in (systemd)`——首轮回归 case-28/30 零告警。原因：pid 1 恒在几乎所有进程的 8 层祖先链内，豁免 systemd 等于豁免全世界。删掉豁免，教训写进用例库 README：祖先链豁免只能用非 pid-1 的 comm。

**pkill 按 exe 永不命中（G21）。** case-30 按 exe = /usr/bin/pkill 写规则，零命中；翻 events.db：comm=pkill、exe=/usr/bin/pgrep。pkill 是指向 pgrep 的符号链接，exe 富化解析的是真实路径，按"调用名"区分行为的工具（pkill vs pgrep、killall vs pidof）按 exe 写规则要么漏报要么混报。改按 comm（argv[0] 前 15 字符）判定，可伪造的权衡写进 fpr_note；busybox/toybox 家族同款，v2 方向是 exec 事件同时带未解析的原始路径。

**rsyslog 的写盘线程不叫 rsyslogd。** evasion-clear-security-log 的 comm 白名单写了 rsyslogd，回归期间每条 auth.log 写入都在误报，还挤占 10s 节流窗口、把 case-27 第二轮的真实告警顶掉。真凶：auth.log 的实际写入者是 rsyslog 的写盘线程，comm 是 `rs:main Q:Reg`——含空格、exe 富化为空，白名单形同虚设。改成 `rs:main`/`rs:action` 前缀豁免（含空格的裸串在 YAML plain scalar 里冒号+空格非法，只能落到前缀）。

这三个 bug 的共同点：规则、引擎、探针各自单测都是绿的，拼起来在真实系统上一跑就漏。零件合格不等于机器合格——30 用例两轮连跑存在的意义，就是专治这种"集成病"。

## 实测数据

| 指标 | 目标 | 实测 | 判定 |
|---|---|---|---|
| 攻击用例回归 | 30 用例 ×2 轮，≥90% | 60/60（exit=0） | ✓ |
| core 规则包 | ≥22 条 | 24 条（+examples 3 = 27） | ✓ |
| 误报专项 D3 | 日常操作零新增误报 | 8 条新规则命中 1 条（G19 所限不可收紧，口径同 W6 nc 先例），2 条当场收紧 | ✓ |
| unit | 全绿 | 110/110 | ✓ |
| 单实例锁 | 同 config 第二实例拒启 | flock 拒启 + kill -9 自动释放，单测覆盖 | ✓ |
| RSS 红线复核 | ≤150MB | 数据待补（见 W7 S5 报告） | ◐ |
| syslog 双通道 | 外发对账误差 0 | 通道已落地，对账数据见 W7 S5 报告 | ◐ |

## 下周预告（W8）

等保/CIS 报告打磨；引擎欠账清零——G11 SUID 位判定（渲染保留完整 mode）、G19 cmdline 采集（v2 草案已存档）、G21 exe 符号链接原始路径、case-07 富化竞态专查；集成测试预演。

## 素材索引

- 集成三连：commit 235ae96（fail-fast + inode 自动登记 + 单实例锁）、`src/common/instance_lock.cpp`、`src/detect/rule_loader.cpp`（ExtractFilePathRefs）
- 三个真 bug：`docs/fpr-w7d3.md`（F2/F3）、`docs/rule-engine-gaps.md` G19/G20/G21、`tests/attack-cases/README.md` W7 D3 设计说明 4/5/7
- 规则包：`rules/core/mining-ta0040.yaml`、`defense-evasion-ta0005.yaml`；关联设计 `docs/mining-correlation-design.md`
- 提交纪律：`CONTRIBUTING.md`；回归：`tests/attack-cases/run_all.sh`（30 用例 ×2 轮）
