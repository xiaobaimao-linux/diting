# W10 S2 全新安装矩阵（W9 补考 + W10 验收轮）

> 日期：2026-11-02。对象：S1 修复后双版本预编译 tarball（`dist/diting-v1.0.0-ubuntu-{22.04,24.04}-x86_64.tar.gz`，内嵌 install.sh 与仓库 d95ff98 一致）。
> 前置：S1 五条卡点修复全部落盘（libbpf vendored 静态链接 / monitor 与 check 配置分离 / rules 随包 / 双版本预编译 tarball / install.sh 源码兜底），tarball 为 S1 最终产物（已校验内嵌脚本与仓库逐字节一致）。

## 环境

| 机 | IP 尾号 | 系统 | 内核 | tarball |
|----|---------|------|------|---------|
| A | .167.217 | Ubuntu 24.04.5 LTS | 6.8.0-147-generic | ubuntu-24.04 版 |
| B | .118.91 | Ubuntu 22.04.5 LTS | 5.15.0-198-generic | ubuntu-22.04 版 |

## 任务 1：双机重置

停服务、删 unit、清 `/etc/diting` `/var/lib/diting` `/var/log/diting` `/usr/local/bin/diting` 后自查，双机三行证据均为零残留：

```
1) which: 0 个残留      （which diting monitor 为空）
2) unit: 0 个残留       （systemctl list-unit-files 无 diting）
3) paths: 0 个残留      （上述路径均不存在）
```

**双机干净态确认 ✓**

## 任务 2：全新安装（用户视角，严格按 README 方式一）

步骤：`tar xzf <tarball>` → `cd <目录>` → `sudo bash install.sh` → `sudo systemctl start diting`，全程未跳步、未用开发机便利脚本。

| 机 | 解压→start 成功耗时 | 红线 <2min | 结果 |
|----|--------------------|-----------|------|
| A | 4s | ✓ | active |
| B | 3s | ✓ | active |

装完即验（双机一致）：

- 服务 active；日志 `[rule_engine] loaded 30 DSL rules from /etc/diting/rules/core` → **rules=30 ✓**
- `cat /etc/shadow` 触发告警落库 `/var/lib/diting/baseline.db` alerts 表：`FILE-SHADOW-001 critical` + `dsl.cred_read_shadow_whitelist high` → **告警通 ✓**

**安装过程零卡点**（前置检测一次通过，预编译路径免工具链，文档步骤与实测逐字对得上）。

## 任务 3：幂等复装

同 tarball 同命令复装：install.sh 先停运行中服务再覆盖安装，复装后 `systemctl start` → active，双机 ✓（W9 幂等结论保持，无回退）。

## 任务 4：36 用例 × 2 轮 × 双版本矩阵

| 机 | r1 | r2 | flake 明细 | RSS 峰值 | reserve_failed | bus.depth.hi |
|----|----|----|-----------|---------|----------------|--------------|
| A | 36/36 | 36/36 | 无（复跑亦 72/72） | 141.4 MB | file/proc/net/priv 全 0 | 1（queue_full 全 0，pushed 11856） |
| B | 32/36 | 32/36 | 无 flake——4 用例三轮连挂，判 FAIL | 119.6 MB | file/proc/priv 全 0（net 探针未加载无计数） | 1（queue_full 全 0，pushed 12010） |

RSS 红线 150MB（云上基线 A 144.0 / B 133.7）：A 141.4 ✓（低于基线）、B 119.6 ✓（低于基线，主因 net_watch 未加载少一类消费者），**均不逼近红线，不立内存瘦身项**。

- A 机两轮全绿（首次跑与补 stats 复跑各 72/72），探针模式 LSM (ring buffer)。
- B 机 case-01 / case-23 / case-24 / case-34（全部依赖 network.connect / dns 遥测）r1、r2 及第三轮复跑连续失败，共 8 条 FAIL/轮跑——**非 flake，根因在探针加载期**：`net_watch_bpf` 的 `tp_sys_enter_sendto` 在 5.15 verifier 处 EPERM(-13) 加载失败（日志首行 `R1 type=ctx expected=fp`），monitor 按设计降级"仅文件监控"，network/dns 事件为零。同二进制在 A 机（6.8）全部通过。已登记 **G25**（docs/rule-engine-gaps.md），疑 S1 libbpf 0.5→1.4.5 vendored 切换引入，未现场修，排期由人裁决。
- B 机 chown 已知边界：`file_chown_hook` 在 5.15 加载 -22 → 自动降级去 chown hook（日志有 warning），本轮 36 用例中无 chown 依赖用例，**边界记账 0 条**。
- 结论：A ✓；B 在 flake 政策下 **FAIL（4 用例，单根因 G25）**——安装/启动/文件&权限&命名空间检测面全部正常，缺口集中在 5.15 网络遥测。

矩阵产物（云机 `/root/matrix-w10/`）：`matrix-A.out`/`matrix-A2.out`、`matrix-B.out`/`matrix-B2.out`、`stats-last.txt`、`/tmp/bg-attack-cases/monitor.log`。

## 卡点清单

**安装侧零卡点**（前置检测一次通过、文档步骤与实测逐字对得上、耗时秒级）。
矩阵执行侧 1 条环境卡点（非安装缺陷）：run_all.sh 要求 ROOT_DIR 有 baseline.db，干净机器需先种子一份空库——属测试基建口径，已备注。

## 新增缺口

**G25**：libbpf 1.4.5 vendored 后 net_watch 在 5.15 加载失败（tp_sys_enter_sendto EPERM），网络/DNS 遥测整体缺失 → B 机 4 网络用例 FAIL。详见 docs/rule-engine-gaps.md G25（现象 + 复现路径 + 影响面 + 临时规避，排期由人裁决）。
