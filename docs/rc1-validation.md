# W10 S3 · v1.0.0-rc1 发布前全链路验证（A 机，干净机器）

> 日期：2026-11-03。对象：`dist/diting-v1.0.0-rc1-ubuntu-24.04-x86_64.tar.gz`（容器 ubuntu:24.04 构建，rc=0）。
> 机器：A（114.55.167.217，Ubuntu 24.04.5 LTS / kernel 6.8.0-147-generic）。
> 物料 sha256：`0e9e681df1500a23350d4951e6efc6bcf507ec312c1b9fa9a9d534d4e129ca00`（scp 后 A 机复算一致）。
> 性质：**发布前最后一道闸**——干净机器从零走"装 → 起 → 告警 → 落库 → 报告 → 冒烟"全链路。

## 0. 重置（干净态三行证据）

停服务、disable、删 unit、清 `/usr/local/bin/diting` `/etc/diting` `/var/lib/diting` `/var/log/diting` `/opt/diting*` 后自查：

```
1) which: 0 个残留      （which diting 为空）
2) unit:  0 个残留      （systemctl list-unit-files 无 diting）
3) paths: 0 个残留      （上述路径均不存在）
```

**干净态确认 ✓**

## 1. 安装（计时）

```
tar xzf diting-v1.0.0-rc1-ubuntu-24.04-x86_64.tar.gz
cd diting-v1.0.0-rc1-ubuntu-24.04-x86_64 && bash install.sh
```

- 解压+安装合计 **0.78s**（预编译路径免工具链，前置检测一次通过，零卡点）。
- 版本验证：`diting --version` → `diting v1.0.0-rc1` ✓

## 2. 启动

`systemctl start diting` → **active**；日志 `loaded 30 DSL rules from /etc/diting/rules/core` → **rules=30 ✓**；NRestarts=0。

## 3. 触发告警（3 类不同规则）

```
cat /etc/shadow          # FILE-SHADOW-001(critical) + DSL cred_read_shadow_whitelist(high)
cat /etc/gshadow         # FILE-GSHADOW-001(critical)
echo >> /etc/crontab     # FILE-CRONTAB-001(high) + DSL persist_crontab_tamper(high)，已复原
```

## 4. 告警落库

`diting alerts -n 10` 实得 **5 条告警**（5 个不同 rule_id，critical×2 / high×3），进程/用户/时间戳字段完整，落库 `/var/lib/diting/baseline.db` alerts 表 ✓：

```
[CRITICAL] FILE-SHADOW-001   /etc/shadow   read   sshd(pid) root
[HIGH]     Cred Read Shadow Whitelist        /etc/shadow   file.read cat(pid) root
[CRITICAL] FILE-GSHADOW-001  /etc/gshadow  read   cat(pid)  root
[HIGH]     FILE-CRONTAB-001  /etc/crontab   write  bash(pid) root
[HIGH]     Persist Crontab Tamper            /etc/crontab   file.write bash(pid) root
```

## 5. check / CIS 报告产出

- `diting check -c /etc/diting/check.yaml`：首跑 0 通过/5 失败——**非缺陷**，随包 check.yaml 的 hash 为 `PLACEHOLDER_*` 占位符（文件头注释要求现场替换）。按注释替换为本机实测 sha256 后复跑：**5 通过 / 0 失败**，HTML 报告生成 ✓（`/var/log/diting/report-*.html`）。
- `diting cis check`：默认路径报 `bad file: cis/cis-baseline-v1.yaml`——**真缺口 G26**（定义文件未随 tarball 分发，见 docs/rule-engine-gaps.md）。按规避口径 `diting cis check --defs <定义文件>`：**40 项全判定，pass 19 / fail 21 / warn 0**（fail 为云镜像真实不合规项），`diting cis report` 出 40 行结果表 ✓。

## 6. 30s 冒烟

monitor 连续运行中采样 t0/t1（间隔 30s）：

- **bus.queue_full.hi 四路 = 0**（lo 四路、reserve_failed 四探针、backpressure_drop、batch_overflow、store_failed 同 0），t0→t1 无增长 ✓
- RSS：t0 141688 kB → t1 141760 kB = **138.4MB**（红线 150MB；低于冒烟基线 144.4 与云上峰值 A 141.4）✓
- 服务 active、NRestarts=0 ✓

## 结论

全链路 6 步全绿：重置 ✓ / 装（0.78s）✓ / 起 ✓ / 告警 5 条落库 ✓ / check+CIS 报告 ✓ / 冒烟 bus.hi=0、RSS=138.4MB ✓。

**新增缺口**：G26（CIS 定义文件打包遗漏，临时规避 --defs，排 rc2/正式版修复）。

## 附：tarball sha256 清单（任务 2）

| 文件 | sha256 |
|---|---|
| diting-v1.0.0-rc1-ubuntu-22.04-x86_64.tar.gz | 4757e7f84df9bfe6e92846b350ef57f1946df7d3f5df871928db88e3e141287a |
| diting-v1.0.0-rc1-ubuntu-24.04-x86_64.tar.gz | 0e9e681df1500a23350d4951e6efc6bcf507ec312c1b9fa9a9d534d4e129ca00 |
