# W9 集成测试预演清单

> 日期：2026-10-27。性质：W9 集成测试预演（ rehearsal ），不是开发周——本周不写新引擎能力，
> 目标是把"零件合格"推进到"整机合格"：36 攻击用例 ×2 轮、CIS 40 项、事件总线/落库链路、
> 云主机 72h 长跑中期数据回收一次跑齐，顺根治当前唯一登记的 flake（case-06）。
> 事实来源：`tests/attack-cases/README.md`、`docs/rule-engine-gaps.md`（G1–G24）、
> `tests/attack-cases/run_all.sh`、`tests/run_tests.sh`、`cis/cis-baseline-v1.yaml`、
> `docs/cis-baseline-v1.md`、W8 计划骨架（`docs/calibration-w7.md` §2）。

## 1. 范围与目标

预演覆盖四条链路，每条都有明确的过线标准（见 §5）：

| 链路 | 覆盖内容 | 入口 |
|---|---|---|
| 攻击用例回归 | 36 用例 ×2 轮连跑（72 项判定），验证 DSL 规则告警 + 遥测事件落库 | `tests/attack-cases/run_all.sh` |
| CIS 配置基线 | 40 项检查复跑，判定结果与 W8 基准对账无回归 | `cis/cis-baseline-v1.yaml`（可读源 `docs/cis-baseline-v1.md`） |
| 事件总线/落库链路 | 预演全程 `bus.queue_full.hi.*` 四路全 0、内核侧 reserve_failed 无增量，告警落 `/var/lib/diting/baseline.db` 对账 | run_all.sh 的 monitor.log + 计数器 |
| 云主机 72h 长跑 | 两台云主机 soak 中期数据点回收（RSS/CPU/reserve_failed），见 §6 | soak.log |

目标一句话：**用跑生产的方式跑测试**——单实例锁（G16）、fail-fast（G17）、节流轮次（throttle=10s、轮间 12s）全部按真实部署形态执行，不允许为预演临时降级配置。

## 2. 用例清单（组级概览）

36 用例明细见 `tests/attack-cases/README.md` 用例清单表，此处只列分组与测试重点：

| 组 | 用例 | 来源 | 测试重点 |
|---|---|---|---|
| W4/W5 基础 | case-01~06 | 基础链路 | 反弹 shell、/etc/shadow 读取、chmod 777、容器场景（docker.sock、挂载基线文件篡改）、批量敏感读取；容器归属（container_id 短 ID、祖先链 runc/containerd-shim） |
| W6 D1 规则包 | case-07~14 | 反弹 shell/凭据规则 | 解释器派生 shell（G24 已根治）、双用途工具、tmp 无扩展名执行、webshell comm 伪造；凭据类替身写入（inode 稳定性：只追加/原地覆盖，禁 rm 重建） |
| W6 D2 规则包 | case-15~22 | 提权/持久化规则 | SUID 高位精确判定（G11 已修复）、ptrace/内核模块/unshare userns；crontab/systemd/ld.so.preload 替身；case-22 与 case-04 同动作不同验证对象（DSL 告警维度） |
| W7 D3 规则包 | case-23~30 | 挖矿/防御规避规则 | 矿池端口/DNS/矿机名/shm 命中域互斥（case-26 双向断言）；G19 cmdline 已修复后 stop-audit 去退化，chattr/kill-security-tool 残余边界见 fpr_note；pkill 按 comm 判定（G21 定型） |
| W8 S2 AI 专项 | case-31~36 | AI 资产保护规则 | 模型文件读/删/目录访问 + MaybeBoostForAi 升级联动双重断言（severity_origin/severity + escalated=1）；AI 工作负载外连负面对照；CUDA/GPU 替身路径（无 GPU 机器 G18 warn 降级为预期） |

**入口**（唯一标准跑法，run_all.sh 内置前置检查、替身准备、monitor 启停与两轮连跑）：

```bash
sudo -v                          # 先缓存凭据
sudo -n bash tests/attack-cases/run_all.sh
```

退出码 0 = 72 项（36 用例 ×2 轮）全 PASS。单用例重跑（monitor 已在跑时）：
`bash tests/attack-cases/case-XX-*/run.sh <tag>` + `verify.sh <tag>`。
unit/integration/e2e 周检入口为 `tests/run_tests.sh`（make unit + 六个单测程序 + integration/test_check.sh + e2e/test_workflow.sh）。

## 3. flake 政策

当前登记在册的 flake 只有一个：**case-06**（进程退出竞态导致 container_id 为空，详见 §4 与
`tests/attack-cases/README.md` 已知边界节）。case-07 同族竞态已于 W8 根治（G24，2026-10-26），不再计入。

政策三条，预演期间严格执行：

1. **重跑上限 2 次，仍失败即 blocking。** flake 标记的用例首轮 FAIL 允许单独重跑至多 2 次；
   第 3 次仍失败即视为真回归，预演整体判 FAIL，不得以"偶发"放行。
2. **flake 不得静默跳过。** 任何被标记 flake 的用例必须登记进 README 已知边界节（用例编号、
   竞态对手、根因方向），verify 断言不得为绕过 flake 而放宽。
3. **新增 flake 必须 24h 内归因。** 预演中跑出的任何间歇性失败（首轮 FAIL、重跑即过）一律先按
   真 bug 对待：24h 内完成归因并定性（竞态/环境抖动/真回归），登记编号；归因为环境抖动的也要
   写清抖动源（参考先例：W7 背景噪声致告警落库峰值 ~8s，lib.sh wait_flush 2s→4s）。

## 4. case-06 根治排期（W9 内完成）

**根因方向**（W8 S3 已定位，见 README 已知边界）：与 G24（case-07）同族的"消费时 /proc 富化
竞态"，但对手是**进程退出**而非再 exec——容器内 `sh` 执行 echo 内建命令写完即退，存活仅毫秒级；
exec 事件消费滞后于进程退出时，`container_id_of(pid)` 读 `/proc/<pid>/cgroup` 失败，告警与事件的
container_id 为空。内核侧无丢包（reserve_failed=0），与传输层无关。

**与 G24 的同族关系**：G24 的对手是短寿进程原地再 exec（消费侧读到新映像），已在用户态用
"事件自带 pe.exe 复评兜底"根治；case-06 的对手是进程已退出、/proc 整个消失，用户态无兜底对象，
根治方向同 G24 的 v2——**内核侧在事件时刻捕获容器归属（task cgroups）随事件携带**；
备选缓解：fork 事件即填 container_id 缩小竞态窗口（属缓解非根治，优先级低于前者）。

**排期**（沿用 W8 骨架格式）：

| 日 | 内容 | 验收（一句话） |
|---|---|---|
| D1 | case-06 复现定位：构造毫秒级容器进程连跑统计 flake 率，确认 /proc 读失败路径 | flake 可稳定复现（≥10%），失败点定位到 container_id_of 读 /proc/<pid>/cgroup |
| D2 | 根治方案定型：BPF 侧事件时刻读 task cgroups 随事件携带 container_id | 方案评审过线（内核侧捕获），字段随 exec/file 事件下发，用户态不再事后读 /proc |
| D3 | 修复落地：事件结构 + 渲染/落库链路 + case-06 verify 口径 | case-06 连跑 10 遍 container_id 全非空，G21/G24 语义不回退 |
| D4 | 回归：36 用例 ×2 轮 + unit 全绿 | 72/72，unit 全绿，无新增 flake |
| D5 | 预演正跑 + CIS 40 复跑 + W9 校准纪要 | 准出标准全过（§5），纪要落档 |

## 5. 准入/准出标准

**准入**（预演开跑前）：周检全绿——`tests/run_tests.sh` 的 unit/integration/e2e 全部 exit=0；
monitor 以生产形态可启动（fail-fast 不触发、单实例锁正常、规则加载无新增 warn 异常）。

**准出**（预演通过条件，四条同时满足）：

| # | 标准 | 判定来源 |
|---|---|---|
| 1 | 36 用例 ×2 轮全过（72/72，exit=0；flake 政策内重跑计入但须登记） | run_all.sh 汇总 + results.txt |
| 2 | CIS 40 项无回归（判定结果与 W8 基准逐项对账，PASS/FAIL 无一变差） | cis-baseline-v1.yaml 复跑记录 |
| 3 | 预演全程 `bus.queue_full.hi.*` 四路全 0（事件总线高优零丢失） | monitor 计数器 |
| 4 | 无新增 flake（24h 归因政策下净登记为 0；case-06 根治后从已知边界摘除） | README 已知边界节 + 归因记录 |

## 6. 云主机长跑联动

两台云主机 72h soak 与预演并行，**预演期间不得重启云主机上的 monitor**——soak 的价值恰在
"同一实例长时间运行"，重启即作废数据点。

| 主机 | 环境 | 回收内容（soak.log） |
|---|---|---|
| 云主机 A | Ubuntu 24.04，kernel 6.8（LSM 主路径） | RSS 峰值/均值、CPU 均值、reserve_failed 增量、bus.queue_full.hi |
| 云主机 B | Ubuntu 22.04，kernel 5.15（旧内核兼容路径） | 同上，重点看旧内核下探针降级形态的长稳表现 |

联动要点：

1. **中期回收**：W9 中期（D3 前后）各取一次数据点，对照红线 RSS ≤150MB、CPU ≤3%、
   reserve_failed 无增长；数据落进 W9 校准纪要实测表。
2. **互不干扰**：云主机 soak 不跑攻击用例（攻击回归只在本机实验环境跑），预演侧的任何操作
   不 ssh 进云主机重启/升级 monitor。
3. **异常处置**：soak 期间云主机 monitor 若 crash/被 OOM，按新增 flake 同款 24h 归因政策处理，
   登记后由主线程决定是否重启——预演侧不得擅自处置。

## 素材索引

- 用例库：`tests/attack-cases/README.md`（36 用例清单 + 已知边界）、`tests/attack-cases/run_all.sh`
- 周检入口：`tests/run_tests.sh`；提交纪律（动 rules/ 必跑回归）：`CONTRIBUTING.md`
- CIS：`cis/cis-baseline-v1.yaml`（机器源，40 项）、`docs/cis-baseline-v1.md`（唯一事实来源）
- 缺口登记：`docs/rule-engine-gaps.md`（G24 = case-07 竞态已根治；case-06 同族根治排 §4）
- 计划格式沿袭：`docs/calibration-w7.md` §2 W8 计划骨架
