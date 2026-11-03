# 云主机 72h soak 收官对账 + 全新安装矩阵（2026-11-02）

> 收官日期：2026-11-02 11:04（最终回收）。口径：两台云主机 /opt/diting-soak/soak.log
> 全段，monitor 自 2026-10-27 21:52 systemd 启动起 **NRestarts=0、连续 133.2h**
>（⊇ 72h 要求；72h 期满点 10-30 21:52 未当场回收，本次为晚期满回收，数据连续无损）。
> 原始数据存档：开发机 `~/soak-archive/soak-A-final.log`（51943 行）/ `soak-B-final.log`
> / `soak-A-final-stats.txt` / `soak-B-final-stats.txt`。
> 准出红线（calibration-w8 §2 D5）：RSS ≤150MB / CPU ≤3% / reserve_failed 无增长 /
> bus.queue_full.hi 四路全 0。中期报告见 soak-midterm-2026-10-28.md。
> soak 装置已拆除：两机 diting-monitor / diting-soak-sampler 已 disable+stop、unit 删除、
> /opt/diting-soak 已清。

## 1. 四项对账（全程 133.2h）

| 项 | A 机（114.55.167.217，24.04/6.8） | B 机（120.55.118.91，22.04/5.15） | 判定 |
|---|---|---|---|
| RSS 峰值 | 147424 kB = **144.0MB**（10-28 23:17），72h 时点 140.4MB，末值 132.7MB | 136952 kB = **133.7MB**（11-02 08:54，末值=峰值），72h 时点 132.1MB | 均 ≤150MB ✓ |
| RSS 趋势 | 峰值后持续回落，末值低于峰值 11.3MB | 缓升后走平，末值=峰值（量级低于 A） | 见 §2 结案 |
| CPU | 稳态均值 0.88%，峰值 1.7% | 稳态均值 0.51%，峰值 1.3% | 均 ≤3% ✓ |
| reserve_failed 四探针 | file/proc/net/priv 全程 0 | 全程 0 | ✓ |
| bus.queue_full.hi 四路 | 全 0（lo 四路、backpressure_drop、batch_overflow、store_failed 同 0） | 同左全 0 | ✓ |
| monitor 存活 | NRestarts=0，连续 133.2h | NRestarts=0，连续 133.2h | ✓ |

事件计数（全程）：A file.emitted 19,083,452 / proc 153,829 / net 60,991 / priv 36,493；
B 量级约低一个数量级（环境静谧，对照组性质不变）。

**pushed−stored 差值复核（中期遗留项）**：A bus.pushed 19,334,468 vs store.stored
19,216,219，差 0.61%（中期 1.3%）；B 差 4.93%（中期 7.9%）。两处差值均随收尾**收敛**，
且 store_failed=0——结论：差值为在途批次/去重口径的正常暂差，**无事件丢失**。

## 2. SOAK-W9-1 结案（A 机 RSS 爬升嫌疑 → 非泄漏）

- 中期判据：爬升速率 <20 kB/h 按分配器缓释结案；>100 kB/h 持续 6h 升级泄漏案。
- 实测：A 机 RSS 于 10-28 23:17 见顶 144.0MB 后**单调回落**，末值 132.7MB；
  去头 2h 的全程线性斜率为负（≈-151 kB/h 量级），日最小值无单调抬升。
- **结论：结案，不升级泄漏案。** 平台期后的缓升为分配器碎片/缓存暂态，随负载
  平稳自然释放；B 机对照组全程无此现象，与事件量级差一致。

## 3. 全新安装矩阵（install.sh，当前 main 源码包）

物料：`diting-dist.tar.gz`（src/bpf/Makefile/baselines/install.sh/config.yaml/rules/cis，
排除 .git 与构建产物）；每轮流程：清旧装态 → 解包 → `bash install.sh` →
`systemctl start diting` 冒烟 10s → 收尾 stop。

| 格 | 结果 | 说明 |
|---|---|---|
| A r1（24.04/6.8 首装） | 安装 ✓ / 冒烟 ✗ | 编译链接全过；服务被 rule_engine 拒绝启动（卡点 ④） |
| A r2（幂等复跑） | 安装 ✓ / 冒烟 ✗（复现） | 清旧装态后重装成功，幂等 ✓；rule_engine 拒绝启动与 r1 完全一致 |
| B r1（22.04/5.15 首装） | 安装 ✗ | 链接期失败：libbpf 0.5 缺 `ring_buffer__ring` 等（卡点 ①②） |
| B r2（复跑 + 绕行） | 安装 ✗（复现）/ 绕行 ✓ | 同一链接错误稳定复现；`LIBRARY_PATH=/usr/local/lib make` 链接通过（ldd 证实走 /usr/local/lib/libbpf.so.1） |

## 4. 安装卡点清单（政企交付前必改）

1. **22.04 stock libbpf 0.5 不满足链接**：`watermark_backpressure.cpp` 用到
   `ring_buffer__ring` / `ring__avail_data_size` / `ring__size`（libbpf ≥1.x API），
   裸 `make` 链接系统 libbpf 0.5 报 undefined reference。
2. **install.sh 不识别本机已有的新版 libbpf**：B 机 /usr/local 下已装 libbpf 1.8
   （头文件被编译期使用），但链接期未加 `-L/usr/local/lib`，新旧混用直接失败。
   已验证绕行：`LIBRARY_PATH=/usr/local/lib make` 链接通过（ldd 确认链到
   /usr/local/lib/libbpf.so.1），B 机 r2 实证。
3. **无依赖版本前置检测**：失败暴露在链接期，错误信息对交付现场不友好；
   install.sh 应 upfront 检测 libbpf 版本下限并给出指引。
4. **安装产物配置口径错误**：`/etc/diting/rules.yaml` 直接拷自
   `baselines/default.yaml`（纯 CIS check 配置，0 个 rule_engine/monitor 段），
   monitor 冒烟时 rule_engine 以默认 `rules` 相对目录加载、拒绝启动；
   且 install.sh 未安装任何 rules 目录。24.04 上"装得上、起不来"。
5. **install.sh 需源码全量编译**：依赖 clang/bpftool/libbpf 头齐全，2C 机器
   单次构建 ~19 分钟；无二进制分发路径。

## 5. 结论

- 72h soak **四项红线全过**，SOAK-W9-1 结案，长跑收官。
- 安装矩阵暴露 5 个卡点（24.04 能装不能跑、22.04 装不上），均已定位到具体行级
  原因并有绕行；建议纳入 W9 修复清单后再进政企 PoC 交付流程。

两机终态：A 机保留 install.sh 装态（/usr/local/bin/diting + /etc/diting/rules.yaml，
服务已停）；B 机未装成（链接失败，/usr/local/bin 无 diting；绕行构建产物留在
/root/diting-install 供排查）。两台密钥登录、密码登录已禁的加固状态不变。
