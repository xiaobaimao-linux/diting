# W6 开发日志：规则包 3→19，和一台诚实的 CIS 引擎

> 状态：W6 收官。core 规则包 16 条落地（执行/凭据/提权/持久化四战术），攻击用例库 6→22 并挂进两轮回归；CIS 引擎 40 项全判定、HTML/JSON 报告导出，开发机实测 pass 19 / fail 21；AI 告警升级上线（升一级封顶 critical，落库可审计）；规则引擎缺口登记到 G16，其中 G3 当周修复。

## 本周做了什么

**1. 规则包 3→19：ATT&CK 覆盖之路。** W5 末规则引擎只有 3 条示例规则。本周 core 规则包 16 条分四个文件落地，对应四个战术：exec-ta0002（解释器反弹 shell、双用途工具、可疑临时目录二进制、web 服务派生 shell）、cred-ta0006（shadow 读取、passwd 篡改、authorized_keys 篡改、shell history 清除）、priv-ta0004（SUID 创建、ptrace 附加、内核模块加载、userns 逃逸苗头）、persist-ta0003/0005（crontab、systemd unit、ld.so.preload、容器内 docker exec）。每条规则带 ATT&CK 映射（5 个战术、17 个技术）、severity、误报说明 fpr_note。配套攻击用例从 6 个扩到 22 个，run_all.sh 两轮连跑挂成回归网。规则不是写出来的，是被用例打出来的——G15（new_mode 渲染与文档不符）就是 case-15 首轮 FAIL 踩出来的。

**2. 误报治理：两轮专项，宁留告警不放水。** D1 用 7 组日常操作扫首轮 8 条规则，真命中只有 1 条：`nc -zv` 端口探测命中双用途工具规则——nc 的探测与反弹在 exe 维度不可分（G1 无 cmdline），任何按 exe 的豁免都会同时豁免攻击载荷，只能保持规则、把研判方法写进 fpr_note。联调期另收紧 3 条：两条规则的祖先列表移除 node（开发机 vscode-server 的 node 链几乎在所有进程的 8 层祖先内，曾每 ~10s 误命中一次）、history 清除规则加 shell exe 白名单。D2 换 apt/systemctl/gcc/sudo 操作集扫新 8 条：**零命中**；命中的全是 D1 规则与 FIM 规则，当场再收紧 2 条（cron 读 shadow、apt-key 派生 dash，均窄化到具体 comm）。dpkg-preconfigure(perl) 读 shadow 无法安全豁免——按 exe 豁免 perl 等于放行一切 perl 脚本，维持告警按祖先链人工研判。

**3. 缺口诚实记录：G 系列登记到 16 条。** 写规则是最好的引擎审计。本周登记的缺口里最有分量的三条：G3——network/dns/priv/ns 四类事件写了规则不触发也**不报错**（当周修复接入求值，并加加载期 event_type 字面值校验，把"静默失配"这条路封死）；G8——单事件只报首个匹配规则，条件重叠的规则互相遮蔽（实测：祖先列表含 node 时 webspawner 规则全量被遮蔽、0 告警），core 16 条因此做了命中域互斥设计；G9——只 open(O_TRUNC) 不写或纯 truncate(2) 不产生 file.write 事件，清空类手法不可见。每条缺口都带退化方案与 v2 方向，完整清单在 docs/rule-engine-gaps.md。

**4. CIS 引擎：40 项全判定，"20 项 15 个 FAIL"是卖点。** 40 项裁剪清单转录为 YAML 定义，三态（pass/fail/warn）判定引擎 + cis check/report 子命令落库，HTML/JSON 报告带等保 2.0 映射。在开发机（默认安装的 Ubuntu）上实测：前 20 项 pass 5 / **fail 15**，全量 40 项 pass 19 / **fail 21**。这不是糗事——默认配置本来就不安全：PermitRootLogin 开着、口令认证开着、X11 转发开着、swappiness 60、suid_dumpable 没关。核查引擎的价值不是给你一个全绿，而是先让你看见这 21 个 fail 具体在哪、怎么整改。

**5. AI 告警升级上线。** 按 W5 设计实现：告警构建时查 ai_workload 标记，AI 进程触发的告警升一级、封顶 critical；alerts 表新增 severity_origin/ai_boost 两列，升没升、为什么升，事后可审计。单测 13/13。

## 最难的一个问题

G16：多 monitor 实例并存的告警串扰。case-22（容器内 docker exec）出现"同一动作有时命中 core 规则、有时命中 examples 规则"的假象，怀疑过引擎不确定性——真凶是历史会话残留的 monitor：旧实例只有旧规则集，与新实例消费同一批内核事件、各自节流、落同一个告警库，把命中抢成了别的 rule_id。本周的应对是 run_all.sh 启动前清理残留实例，正解（pidfile/flock 单实例锁）排 W7。

本周最后一课是回归网的价值。D5 全量回归抓到 D3 引入的加载器回归：CIS 定义文件进了规则目录，其顶层不是规则列表，单个文件加载失败把整个 DSL 引擎降级为空——16 个 DSL 用例两轮全 FAIL。结果刺眼，但用例库兜住了它，这正是 22 用例两轮连跑存在的理由。归因与修复排期见 calibration-w6.md。

## 实测数据

| 指标 | 目标 | 实测 | 判定 |
|---|---|---|---|
| core 规则包 | 20+ 条（含示例） | core 16 + examples 3 = 19，覆盖 5 战术 17 技术 | 差 1 条，口径见校准纪要 |
| 攻击用例检出 | ≥90% | D2 收紧后 22×2 全 PASS；D5 回归 6/22（加载器回归，非规则问题） | D5 口径 ✗，归因见校准纪要 |
| 误报专项 | 日常操作零新增误报 | D2 新 8 条零命中；累计收紧 5 条，1 条双用途不可收紧已记录 | ✓ |
| CIS 引擎 | 40 项全判定 | pass 19 / fail 21 / warn 0，HTML/JSON 报告导出 | ✓ |
| AI 告警升级 | high→critical 端到端 | 单测 13/13，severity_origin/ai_boost 落库可审计 | ✓ |

## 下周预告（W7）

G16 单实例锁；DSL 文件类规则 inode 注册决策（自动注册 or 加载期警告）；挖矿/防御规避规则补齐 20+ 口径；G9/G10/G15 渲染口径统一；RSS 瘦身（常态 139.3MB，红线 150MB）。

## 素材索引

- 误报专项：`docs/fpr-w6d1.md`、`docs/fpr-w6d2.md`
- 引擎缺口：`docs/rule-engine-gaps.md`（G1–G16）
- CIS：`rules/cis/cis-baseline-v1.yaml`、`docs/cis-report-format-v1.md`
- 回归：`tests/attack-cases/run_all.sh`，D5 日志 `/tmp/w6d5-run_all.log`
