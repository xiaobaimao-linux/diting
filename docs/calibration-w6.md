# W6 校准纪要（W6 收官）

> 日期：2026-10-12。口径：W6 清单按 D1–D5 任务卡还原为 17 项可勾选交付物；
> 实测数据引自 /tmp/w6d5-run_all.log、/tmp/w6d5-cis.log、/tmp/bg-perf/results/ 与当次 monitor 日志。

## 1. 完成率统计

| # | 计划项 | 状态 | 证据 |
|---|---|---|---|
| 1 | core 规则包 exec/cred 8 条（TA0002×4 + TA0006×4） | ✓ | rules/core/exec-ta0002.yaml、cred-ta0006.yaml |
| 2 | 攻击用例 case-07~14 配套落地 | ✓ | tests/attack-cases/，commit b675caf |
| 3 | 误报扫描 D1（7 组日常操作） | ✓ | docs/fpr-w6d1.md，真命中 1 条（nc 双用途，不可收紧） |
| 4 | G3 修复：network/dns/priv/ns 接入求值 + event_type 加载期校验 | ✓ | commit ae19216 |
| 5 | core 规则包 priv/persist 8 条（TA0004×4 + TA0003/TA0005×4） | ✓ | commit a6da2d5 |
| 6 | 攻击用例 case-15~22 配套落地 | ✓ | commit 54a0b46 |
| 7 | run_all.sh 挂 22 用例两轮 + 残留 monitor 清理守卫（G16 防御） | ✓ | 同上 |
| 8 | 误报专项 D2（apt/systemctl/gcc/sudo 操作集） | ✓ | docs/fpr-w6d2.md，新 8 条零命中，收紧 2 条 |
| 9 | CIS 40 项定义转录 yaml | ✓ | cis/cis-baseline-v1.yaml（W7 D1 起移出 rules/） |
| 10 | CIS 三态判定引擎 + cis check/report（前 20 项） | ✓ | commit b066850 |
| 11 | CIS 后 20 项验证，40/40 对账 | ✓ | commit 85a4dc4 |
| 12 | cis report HTML/JSON 导出 | ✓ | 同上，docs/cis-report-format-v1.md |
| 13 | AI 告警升级实现（升一级封顶 critical，severity_origin/ai_boost 落库） | ✓ | 同上，单测 13/13 |
| 14 | D5 全量回归 ≥90% 检出 | ✗ | **5/22 = 22.7%**，归因见下 |
| 15 | D5 CIS 全量无回归 | ✓ | pass 19 / fail 21 / warn 0，与基线完全一致 |
| 16 | D5 性能冒烟 + RSS 红线 | ✓ | 见下方实测 |
| 17 | 规则包 20+ 条口径（W5 排期 §3） | ✗ | core 16 + examples 3 = **19，差 1 条** |

**完成率 15/17 = 88.2%**。另：W5 顺带项「asset collect 挂 cron 分钟级」W6 未排进任务卡，未做（不计入分母，转入 W7 候选池）。

### 偏差归因

1. **D5 回归 22.7%（项 14）——加载器回归，非规则问题。** W6 D3 新增的
   `rules/cis/cis-baseline-v1.yaml`（W7 D1 已移至 `cis/cis-baseline-v1.yaml`）
   顶层不是规则列表，`rules_dir: "rules"` 递归加载时该文件失败
   导致 `LoadRulesDir` 整体返回 false、DSL 引擎降级为空（src/detect/rule_loader.cpp:136、
   src/baseline/monitor.cpp:1815）。case-07~22 共 16 个 DSL 用例两轮全 FAIL 均此一根因；
   底层事件源、内置 FIM 规则均正常。**过程教训：D3/D4 只跑单测与冒烟、未重跑攻击用例，
   回归网空窗 2 天**，D5 才兜住。修复（跳过非 DSL yaml 或 cis 移出递归范围）列 W7 D1 首位。
   flaky 1 例：case-02 r2 的 shadow 读落在 AC-02 节流窗口内，窗口被宿主机 sudo PAM 认证
   （非用例动作）重置——环境噪声 + 用例边界，事件维度实际有记录。
2. **规则包 19 条差 1（项 17）。** 挖矿（M3-4）/防御规避（M3-5）类规则未动工：
   CIS 引擎（D3/D4）实际工作量超预期，"引擎类工作被低估"前科再现（W3→W4 曾重演）。排 W7 D3。
3. **asset collect cron 未做。** W5 校准纪要中的顺带项，W6 任务卡未承接，属流程掉落而非技术阻塞。

### D5 实测

| 项 | 数值 | 判定 |
|---|---|---|
| 攻击用例回归 | 5/22 两轮全 PASS（case-02 flaky：r1 PASS/r2 节流遮蔽），检出率 22.7% | ✗ ≥90% |
| CIS 全量 40 项 | pass 19 / fail 21 / warn 0，与 D4 基线逐项一致 | ✓ |
| unit | 13 个测试程序、116 断言全绿 | ✓ |
| tput 30s（119 条 DSL 规则实载） | 300,000/300,000 入库，bus.queue_full.hi.* 四路全 0，drop 计数零增量 | ✓ |
| 常态 5min | RSS 峰值 138.2MB（W5 基线 139.3，**-1.1MB 无增长**）；CPU 均值 0.70%（+0.13pp） | ✓ |

> RSS 归因：对照实验（examples 3 条 vs 全量 119 条，75s 快照）137.8 vs 138.2MB——
> **DSL 规则 3→119 条仅占 ~0.4MB**；core 16 条与 AI 升级链路常态空转无可见增量，
> 138.2 vs 139.3 的负差属测量噪声。RSS 红线压力暂缓，瘦身优先级下调。
> 性能测试为规避加载器 bug 使用 /tmp 规则副本（core+examples+perf-100，不含 cis），
> 规则实载 119 条，负载口径比仓库当前状态更重，结论保守有效。

## 2. W7 候选池排序建议

| 序 | 候选 | 理由 |
|---|---|---|
| 1 | **规则加载器回归修复**（跳过非 DSL yaml / cis 移出递归范围） | D5 新发现：空引擎状态下全部 DSL 规则失效，是一切检测能力的前提；不修复则 W7 所有规则工作无法验证 |
| 2 | **G16 单实例锁**（pidfile/flock 互斥） | 回归与生产的可信度前提；本周已实测串扰造成 case-22 假失败，防御脚本只是缓解 |
| 3 | **DSL 文件规则 inode 自动注册**（**决策点**：自动注册 or 加载期警告） | 规则包"开箱即用"口径的拦路石：用户写 file.path 规则而未注册 inode 时永远无事件。自动注册体验好但隐式扩大 BPF map 监控面；加载期警告显式但把负担留给用户。**需人拍板后实现** |
| 4 | **挖矿/防御规避规则**（M3-4/M3-5，含用例） | 补 20+ 口径欠账；PRD P0 项；依赖项 1 修复后才能验证 |
| 5 | **Syslog 通道** | 外发完备性（webhook 之外的标准运维通道）；独立性强，可插缝 |
| 6 | **G9/G10/G15 修复**（truncate 钩子 + 渲染口径统一） | 三者同属"采集/渲染口径漂移"，打包做可一次处理历史数据迁移评估；G9 补 path_truncate 钩子有内核侧工作量 |
| 7 | **RSS 瘦身** | 本周实测 138.2MB 无增长（红线 150），压力暂缓；降为监视项，超 145MB 再立项 |

## 3. W7 逐日骨架

| 日 | 内容 | 验收（一句话） |
|---|---|---|
| D1 | 加载器回归修复 + G16 单实例锁 | run_all.sh 22 用例 ×2 轮全 PASS，且同 config 第二实例启动被拒 |
| D2 | inode 注册决策落地（按拍板实现自动注册或加载期警告） | DSL 文件规则在 config 未注册路径时：自动注册生效出事件，或加载期警告可见且文档同步 |
| D3 | 挖矿/防御规避规则 6+ 条 + 配套用例 | core 规则 ≥22 条，新用例两轮 PASS，日常操作扫描零新增误报 |
| D4 | Syslog 通道 + G9/G10/G15 打包修复 | syslog 外发三方对账误差 0；ns.names/new_mode 渲染对齐文档，历史数据迁移方案落文档 |
| D5 | RSS 监视 + 全量回归 + W7 校准纪要 | RSS ≤150MB；22 用例 ×2 轮检出率 100%（加载器修复后口径）；CIS 40 项无回归 |
