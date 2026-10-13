# W7 D3 误报专项（FPR）记录

> 方法（对齐 W6 D2）：单 monitor（tests/attack-cases/config.yaml，128 条 DSL 规则 + FIM 规则）下依次执行日常操作，
> 打标后统计新增 alerts。环境：vscode-server 远程开发机。
> 操作集：`systemctl status/is-active`、`dig google.com`、`dig pool.ntp.org`（专门验证矿池 DNS 规则的 pool. 取舍）、
> `apt-get update`、gcc 编译运行 hello（/root/bgfpr）、`id` / `sudo -n`。
> **结论：本批 8 条新规则命中 1 条（evasion_stop_audit_service，G19 所限不可收紧），其余 7 条零命中。**
> 另：回归期间实测发现 2 处规则缺陷已当场收紧（F2/F3）。

## 命中明细

### F1 systemctl status → dsl.evasion_stop_audit_service ×1【未收紧，G19 所限】

- 现象：`systemctl status cron`（日常运维）命中——规则已退化为"systemctl 执行即报"。
- 定性：exec 无 cmdline（G1/G19），stop/disable 动作与 auditd 目标不可判定，任何收紧都会同时
  放行真实攻击（`systemctl stop auditd` 与 `status` 的可见字段完全一致）。
- 处置：维持告警，priority 已定 medium；fpr_note 已声明"宁噪声勿漏报"取舍与 v2 cmdline 草案
  （`cmdline contains (stop, disable) and contains (auditd, rsyslog)`，见 gaps G19）。
- 验证过的反向点：规则 2 的祖先链未豁免 systemd（pid 1 恒在 8 层祖先链内，豁免即全量静默）。

### F2 rsyslog 写盘线程写 auth.log → dsl.evasion_clear_security_log 持续误报【已收紧】

- 现象：回归期间实测——rsyslog 的写盘工作线程 comm 是 `rs:main Q:Reg`（含空格、exe 富化为空），
  不在原 comm 白名单（rsyslogd），每条 auth.log 日志都误报，且占满 10s 节流窗口挤掉 case-27 r2 的真实告警。
- 收紧：condition 追加 `and not process.comm startswith rs:main and not process.comm startswith rs:action`
  （裸串无法表达含空格 comm；`rs:` 裸写撞 YAML 语法——plain scalar 中冒号+空格非法，故落到 `rs:main`/`rs:action`）。
- 验证：收紧后 FP 操作集（含 ssh/sudo 触发的 auth.log 写入）对该规则零命中，case-27 两轮全过。

### F3 祖先链 systemd 豁免设计错误【已收紧（删除豁免）】

- 现象：规则 2/4 初版写 `not process.ancestors[].comm in (systemd)`，回归首轮 case-28/30 零告警——
  pid 1（systemd）恒在 8 层祖先链内，该豁免等价于全量静默。
- 收紧：删除两条规则的 systemd 祖先豁免，噪声权衡写入 fpr_note；教训记入 README（W7 D3 用例设计说明 5）。

## 反向验证（未命中即正确）

- `dig pool.ntp.org` 未命中 mining_pool_dns_query——裸 `pool.` 关键字刻意未收（contains 是子串语义，
  收则 NTP 查询全量误报），规则只保留矿池厂商/币种特征字。
- `apt-get update` / gcc 编译未命中任何新规则（tmp 执行、矿池端口、kill 家族均未触发）。
- 既有噪声不重复处理：reverse_shell_from_web_service（examples，node 祖先链，W6 F4 已知）、
  exec_webspawner_shell（apt 的 dash+python 祖先链，W6 F2 同款）、AC-02（FIM sudo 读 shadow，设计内）、
  perf_sensitive_read_008（压测规则家族，无实际意义）。
