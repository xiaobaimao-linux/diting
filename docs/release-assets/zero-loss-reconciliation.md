# 133h 浸泡零丢包对账表（2026-10-27 ~ 2026-11-02）

数据来源：开发机 `~/soak-archive/soak-A-final-stats.txt` / `soak-B-final-stats.txt`（原始日志 `soak-A-final.log` / `soak-B-final.log`）。

| 计数器 | A 机（24.04 / 6.8） | B 机（22.04 / 5.15） |
|---|---|---|
| kernel.file.emitted | 19,083,452 | 1,583,467 |
| kernel.file.reserve_failed | 0 | 0 |
| kernel.file.backpressure_drop | 0 | 0 |
| kernel.proc.emitted | 153,829 | 115,121 |
| kernel.proc.reserve_failed | 0 | 0 |
| kernel.net.emitted | 60,991 | 13,126 |
| kernel.net.reserve_failed | 0 | 0 |
| kernel.priv.emitted | 36,493 | 20,821 |
| kernel.priv.reserve_failed | 0 | 0 |
| bus.queue_full.hi.*（4 队列） | 全 0 | 全 0 |
| bus.queue_full.lo.*（4 队列） | 全 0 | 全 0 |
| batch_overflow | 0 | 0 |
| store_failed | 0 | 0 |
| NRestarts | 0 | 0 |

| 收敛项 | A 机 | B 机 |
|---|---|---|
| bus.pushed | 19,334,468 | 1,732,378 |
| store.stored | 19,216,219 | 1,646,965 |
| pushed − stored | 118,249（0.61%） | 85,413（4.93%） |
| bus.depth.hi（观察项） | 1 | 3 |
| bus.depth.lo | 0 | 0 |

说明：五类丢包/失败计数器（reserve_failed、backpressure_drop、queue_full、batch_overflow、store_failed）全程为零，服务零重启。pushed−stored 差值为白名单/规则过滤与在途批次的正常收敛，非丢包（store_failed=0 佐证）。bus.depth.hi 偶发 1/3 为瞬时水位，未触发 queue_full。
