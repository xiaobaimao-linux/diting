# 云主机 72h soak 中期对账（手动补跑）

> 日期：2026-10-28 14:32（采样截至）。口径：两台云主机 /opt/diting-soak/soak.log，
> 仅取 2026-10-27 21:52 systemd 重启后段（A pid=820、B pid=705，各 201 个 5min 数据点，
> 段长 ~16.7h）。原始数据存档：开发机 `~/soak-archive/soak-A-241022.log` /
> `soak-B-2204.log`。准出红线（calibration-w8 §2 D5）：RSS ≤150MB / CPU ≤3% /
> reserve_failed 无增长 / bus.queue_full.hi 四路全 0。

## 1. 四项对账

| 项 | A 机（114.55.167.217，24.04/6.8） | B 机（120.55.118.91，22.04/5.15） | 判定 |
|---|---|---|---|
| RSS 起→止 | 10.4MB（冷启动）→ 142.5MB；平台期 22:00 起 141.2MB → 142.5MB | 13.6MB（冷启动）→ 131.8MB；平台期 131.7MB → 131.8MB | A 见 §2 立案；B ✓ |
| RSS 峰值 | 145960 kB（=段末值，红线内，余量 ~4MB） | 134964 kB（=段末值） | 均 ≤150MB ✓ |
| RSS 趋势 | 平台期后 **连续 9 小时单调爬升**（06:00 均 144579 → 14:00 均 145825，≈+156 kB/h；整段 ≈+83 kB/h） | 平台期后 +128 kB/17h ≈ +7.5 kB/h，实质持平 | A 爬升=泄漏嫌疑；B 无嫌疑 |
| reserve_failed 四探针 | file/proc/net/priv 全程 0 | 全程 0 | ✓ |
| bus.queue_full.hi 四路 | p0_file/p1_ctrl/p2/p3 全程 0（lo 四路同 0；backpressure_drop/batch_overflow/store_failed 全 0；depth.hi 瞬时峰 5） | 同左全 0（depth.hi 瞬时峰 18） | ✓ |
| monitor 存活 + systemd | diting-monitor + diting-soak-sampler 均 active(running)，ActiveEnter=10-27 21:52:27，**NRestarts=0**，pid 820 存活 16h40m | 同左，ActiveEnter=10-27 21:52:26，NRestarts=0，pid 705 存活 16h40m | ✓ |

补充观察（非对账项，不立案）：A 段内 bus.pushed−store.stored 差 33707/2.54M（1.3%），
B 差 27621/349k（7.9%），store_failed=0——差值为在途批次/去重口径，72h 收尾时复核一次；
A CPU 瞬时峰 10.4%（needrestart/apt 活动窗口），稳态 0.5~0.9%，红线口径 ✓。

## 2. 立案 SOAK-W9-1：A 机 RSS 平台期后缓慢爬升（泄漏嫌疑）

- **现象**：A 机（24.04/6.8）RSS 于 10-27 22:00 进入 ~144.6MB 平台，00:00–05:00 完全持平
  （144572 kB 六小时不动），06:00 起每小时均值单调递增，至 14:32 达 145960 kB。
  速率 ≈156 kB/h（近 8h），整段均值 ≈83 kB/h。B 机（22.04/5.15）同窗口无此趋势。
- **排查线索**：A 事件量级远高于 B（file.emitted 249 万 vs 31 万，journal 可见 needrestart
  引发的 exec 风暴与竞态兜底复评高频触发）；爬升段恰在高事件量之后起步——嫌疑方向为
  用户态 exec_eval 解析缓存/分配器碎片随事件量缓涨，而非内核侧丢包（reserve_failed 全 0）。
  内核版本路径差异（6.8 vs 5.15 降级路径）为次要嫌疑。
- **判据与处置**：soak 剩 ~55h，按 83–156 kB/h 外推将在收尾前后触及 150MB 红线。
  10-30 收尾对账时若 A RSS >150MB 或爬升速率不降（连续 6h >100 kB/h），升级为正式
  leak 案：heaptrack/ASan 复跑 A 机构型 + exec_eval 缓存容量上限审查；若速率回落至
  <20 kB/h 则按分配器缓释结案。B 机作对照组继续观察。

## 3. cron 核查（"11:47 定时执行"证伪）

- A 机 `crontab -l`：no crontab for root；B 机同；开发机 sf 用户同空。
- /etc/cron.d/、/etc/crontab 三台均无 soak/对账相关条目；本会话内调度器任务数=0。
- soak.log 中的 11:47 时间戳只是采样器 5 分钟节拍的自然落点（…:42/:47/:52…）。
- **结论：cron 里没有任何对账任务——不是日期设错，也不是 daily 任务，是任务从未安装。**
  "11:47 定时执行"的说法不成立；10-28 11:47 未跑属必然。如需定时对账需显式安装
  （crontab 条目或会话内调度器），本次为手动补跑。
