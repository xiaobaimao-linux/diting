# W8 开发日志：欠账清零之后，把机器搬上云

> 状态：W8 收官。检测力欠账三连清零（G11/G19/G21），AI 专项规则包 6 条 + 用例库 30→36；
> case-07 富化竞态根治（G24）；云主机 72h 长跑上线两台（6.8/5.15 双内核）；踩出并根治
> proc_watch CO-RE 双布局兼容 bug；等保报告 40 项修复命令补齐 + 条款分组视图。周检：回归
> 35/36+36/36（case-06 已知 flake）、unit/integration/e2e 全绿、CIS 40 项 pass 19/fail 21、
> bus.hi 四路全 0、RSS 峰值 147.0MB。

## 本周做了什么

**1. 检测力欠账清零：G11/G19/G21 一刀一个（S1，commit b1cbbbc）。** 三条都是"规则想表达、
引擎给不了"的老账：G11 让 `chmod 4755` 与 `chmod 755` 在规则侧可区分（渲染保留 setuid
高位，rwsr-xr-x vs rwxr-xr-x，基线比对路径刻意保持 0777 不动——动它会给 /usr/bin/passwd
这类合法 SUID 文件刷 perm_changed 误报）；G19 把 exec cmdline 前 255 字节采进事件
（选型 256B 而非 4KB 的理由是内存账：payload cap 不涨、总线常驻零增长，4KB 会让常驻 ×7
直接冲破 RSS 红线），stop-audit 规则当场去退化——`systemctl status` 不再误报；顺手抓了
一个附带 bug：255 字节截断可能切断多字节 UTF-8，序列化抛异常能把消费线程干掉（可被构造
argv 利用的 DoS），严格 UTF-8 清洗 + 渲染兜底落地。G21 定型"真实身份看 exe、调用行为看
comm"——pkill/pgrep 这类符号链接双行为工具按 comm 判定，不引入双字段、不动既有 24 条
规则的 exe 语义。

**2. AI 专项规则包 6 条 + 用例 case-31~36（S2，commit a013fe9）。** 模型文件读/删/目录访问、
AI 工作负载外连、CUDA 库注入、GPU 设备访问——PRD M4 的检测面从"资产发现+告警升级"补到
"行为检测"。用例设计两个要点：升级联动断言写死 severity_origin/severity 与 escalated=1
双重校验，防"字段置位但级别没变"的假联动；替身选址按命中域互斥（受管目录外归 file-read、
目录前缀内归 dir-access，G8），外连只到本机外网口地址，不出网卡。

**3. case-07 富化竞态根治 + 一批收尾修复（S3，0bafd35/a2df4f3/3980fcd）。** G24 的根因：
exe 富化在消费线程读 /proc，短寿进程原地再 exec 时读到的是新映像——case-07 的 bash 被
渲染成 /usr/bin/id，exe 名单规则间歇漏报（修复前复现 7/10，修复后 10/10）。修复是"事件
自带 pe.exe（exec 时刻 tracepoint filename，无竞态）与解析结果不一致时复评一次"，详细
分析收口在 `docs/case07-race-analysis.md`。同族遗留 case-06（对手是进程退出而非再 exec，
/proc 整个消失、用户态无兜底对象）根治排 W9，方向是内核侧事件时刻捕获容器归属。同批：
final stats 退出丢失修复、alerts --db/优雅报错、cis 默认全量 40 项、events_perf.db 迁
/tmp/bg-perf（仓库根 1.9GB 不复发）。

**4. 云主机 72h 长跑上线两台（S4）。** 114.55.167.217（Ubuntu 24.04，kernel 6.8）与
120.55.118.91（Ubuntu 22.04，kernel 5.15），密钥登录切换、密码登录禁用，systemd
diting-monitor + diting-soak-sampler 双服务常驻，soak.log 每 5 分钟一个数据点
（RSS/CPU/stats --drop）。这是项目第一次离开开发机跑长稳——也是第一次被真实多内核
环境毒打，见下节。

**5. proc_watch CO-RE 双布局根治（S4 踩出的真 bug）。** 细节见下节。

**6. 5.15 适配两个补丁（S4）。** 22.04 自带的 libbpf 0.5 没有 perf_buffer__new 六参形式
与 ring__* API，主机 2 改用 libbpf 1.8 源码静态链接构建，monitor.cpp 增加 perf_buffer__new
版本兼容封装；5.15 verifier 不认 LSM hook 原型按值 STRUCT 参数（path_chown 的
kuid_t/kgid_t），monitor.cpp 增加加载失败自动降级——禁载 file_chown_hook 重试，CHOWN
检测降级，主机 2 实测降级路径生效（日志 `skeleton load failed (-22) ... retry without
path_chown hook`），其余三探针正常 attached。

**7. 等保报告打磨（S3/S4）。** cis-baseline-v1.yaml 40 项修复命令补齐（0/40→40/40，评审
时逐项可执行）；cis report 新增 --group-by-clause 条款分组视图（src/cis/cis_main.cpp），
报告从"40 行流水账"变成按等保条款聚合的评审视图。

## 用例踩出的真 bug

**proc_watch 在新旧内核上是两个结构体（S4，云主机上线第一天踩出）。** 症状：6.8 云主机上
proc_watch 加载直接失败（load -22），fork/exec/exit 事件全无。根因：sched_process_fork/exit
的 raw tracepoint 结构体在新旧内核布局不同——新内核是 __data_loc 版（动态偏移），6.8 是
定长数组版，且 6.8 的 BTF 里整个缺 exit 结构体。按名 CO-RE 重定位解析失败会毒化整个 prog，
不是"某个字段读错"而是"整个程序加载不了"。修复（bpf/proc_watch.bpf.c）：用
bpf_core_field_exists 判布局、bpf_probe_read_kernel 按手工偏移读，不再赌 BTF 里有没有这个
结构体。6.8 与本机 7.0 双端验证通过，proc_watch attached 字样双端日志可见。已知残留边界：
旧内核（定长数组版布局）上 fork 事件的 comm 走固定数组路径，语义不变但实现路径不同。

这个 bug 的性质和 W7 三个真 bug 相反：那次是"零件各自合格、拼起来漏"，这次是"零件在开发机
合格、换台机器就不合格"——kernel-compat-matrix 上所有"待实测"的格子都是这种债，云主机
长跑存在的意义就是把它们一个个变成实测结论。

## 实测数据

| 指标 | 目标 | 实测 | 判定 |
|---|---|---|---|
| 攻击用例回归 | 36 用例 ×2 轮，≥90% | r1 35/36、r2 36/36（唯一失败 case-06 r1，已知 flake：重跑 2 次 1 PASS 1 FAIL，进程退出竞态间歇性确认，根治排 W9，不算回归） | ✓（flake 登记） |
| unit/integration/e2e | 全绿 | run_tests.sh exit=0：unit 6 程序全绿（58 个 PASS 断言行）、integration 10/10、e2e 全过 | ✓ |
| CIS 40 项 | 无回归 | pass 19 / fail 21 / warn 0（与 W7 基准量级一致；fail 项为本机真实配置差距，非引擎回归） | ✓ |
| bus.queue_full.hi.* 四路 | 全 0 | 回归中期 + 重跑后两次采样均全 0；四探针 reserve_failed 全 0 | ✓ |
| RSS 红线 | ≤150MB | run_all 全程采样（5s×79 点）：min 143.3 / p50 146.4 / 峰值 147.0MB | ✓ |
| CPU | ≤3% 稳态 | 启动峰值 5.7%，稳态 1.1~1.3% | ✓ |
| FIM 冒烟 | 写目标文件产生事件+告警 | file.write 事件（action=alert）+ W2-FILE-002 medium 告警落库，12:39:34 时间戳对账一致 | ✓ |
| proc_watch 探针 | 正常 attached | 本机 7.0 日志 "proc_watch attached (fork/exec/exit)"；云主机 6.8/5.15 双端 attached | ✓ |
| 云主机长跑首值 | reserve_failed=0、bus.hi=0 | A（6.8）：RSS 141.9MB / CPU 0.5%，四路 reserve_failed=0、bus.hi 四路全 0；B（5.15）：RSS 131.1MB / CPU 0.4%，同全 0 | ✓（72h 中段继续看） |

## 下周预告（W9）

集成测试预演周，不写新引擎能力，按 `docs/integration-test-plan-w9.md` 执行：case-06 根治
（内核侧事件时刻捕获容器归属，D1-D3）、36 用例 ×2 轮预演正跑 + CIS 40 项对账（D4-D5）、
云主机 72h 长跑中期数据回收（RSS ≤150MB、CPU ≤3%、reserve_failed 无增长对照红线）。
flake 政策三条严格执行：重跑上限 2 次、flake 不得静默跳过、新增 flake 24h 内归因。

## 素材索引

- 欠账清零：commit b1cbbbc（G11/G19/G21）、`docs/rule-engine-gaps.md` G11/G19/G21 修复记录
- AI 专项：commit a013fe9、`rules/core/ai-security.yaml`（6 条，core 包达 30 条）、`docs/fpr-w8s2.md`
- case-07 根治：commit 0bafd35、`docs/case07-race-analysis.md`、`src/baseline/monitor.cpp:1527-1531`
- proc_watch CO-RE：`bpf/proc_watch.bpf.c`（工作区未提交）、云主机 6.8/5.15 双端日志
- 5.15 适配：`src/baseline/monitor.cpp`（libbpf 版本兼容封装 + chown 降级重试）
- 等保打磨：`cis/cis-baseline-v1.yaml`（40/40 修复命令）、`src/cis/cis_main.cpp`（--group-by-clause）
- 周检数据：`/tmp/test_results.txt`、run_all 日志 `/tmp/run_all_w8.log`、soak.log（两台云主机 /opt/diting-soak/）
- W9 预演：`docs/integration-test-plan-w9.md`
