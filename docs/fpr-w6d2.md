# W6 D2 误报专项（FPR）记录

> 方法：单 monitor（tests/attack-cases/config.yaml，120 条 DSL 规则 + FIM 规则）下依次执行系统日常操作，
> 打标后统计新增 alerts。环境：vscode-server 远程开发机（node 祖先是已知噪声源，见 docs/fpr-w6d1.md）。
> 操作集：`apt update && apt install -y curl`、`systemctl restart cron`、gcc 编译运行 hello world（~/bgfpr）、
> `sudo id` / `sudo -l`。
> **结论：本批 8 条新规则（priv-\*/persist-\*）零命中**；命中全部落在 D1 规则/示例规则/FIM 规则上，明细如下。

## 命中明细（4 类，15 条告警）

### F1 cron 重启读 /etc/shadow → dsl.cred_read_shadow_whitelist ×1（+FIM AC-02 ×1）【已收紧】

- 现象：`systemctl restart cron` 后 cron 子进程（comm=cron，exe 富化为空，祖先 cron←systemd）读 /etc/shadow，命中 DSL 规则与 FIM AC-02。
- 定性：cron 经 PAM 校验用户身份的固有行为，每次重启/任务派发都会发生，高频噪声。
- 收紧：`cred-ta0006.yaml` 条件追加 `and not process.comm in (cron, crond)`（exe 为空只能用 comm；
  comm 可伪造的权衡已写入 fpr_note）。FIM AC-02 无条件表达力，维持告警（配置规则，按设计全量报告 shadow 读）。

### F2 apt update 的 apt-key 派生 dash → dsl.exec_reverse_shell_under_interpreter ×1【已收紧】

- 现象：`apt-key`（dash 脚本）祖先链 gpgv←gpgv←python3←systemd，python3 命中解释器列表。
- 定性：apt 密钥校验的固有行为，D1 fpr_note 已预告"包管理脚本"类噪声。
- 收紧：`exec-ta0002.yaml` 条件追加 `and not process.comm in (apt-key)`（窄化到具体系统工具，权衡同 F1 写入 fpr_note）。

### F3 dpkg-preconfigure（perl）读 /etc/shadow → dsl.cred_read_shadow_whitelist ×1【未收紧，G1 所限】

- 现象：`apt install` 的 dpkg-preconfigure（perl 脚本，exe=/usr/bin/perl，祖先 sh←apt←sudo）读 shadow。
- 定性：debconf 预配置固有行为，但**无法安全豁免**——解释器 exe 是 perl 本体，脚本名在 argv（G1 无 cmdline），
  按 exe 豁免 perl 等于放行一切 perl 脚本。
- 建议：维持告警，按祖先链（apt/dpkg 语境）人工研判；v2 采集 cmdline 后可按脚本路径豁免。

### F4 开发机 node 祖先链 shell → dsl.reverse_shell_from_web_service（examples）×5【已知，不处理】

- 现象：本次操作经 vscode-server 终端执行，所有 bash/dash 祖先链含 node，命中示例规则（其名单含 node）。
- 定性：D1 已实测记录（docs/fpr-w6d1.md）：core 规则刻意移除 node，examples 规则保留 node 作 webshell 兜底——
  开发机噪声与 webshell 检出的既有取舍，不改动。

### 附：AC-02（FIM）对 sudo 读 shadow 告警 ×4

- sudo 的 PAM shadow 读是 FIM AC-02（critical，全量报告 shadow 读）的设计内告警；DSL 变体已豁免 sudo（本次零命中）。
- 不处理：配置规则无白名单表达力，告警量由 FIM 节流（10s）兜底。

## 本批 8 条新规则的噪声评估

| 规则 | 本次日常操作命中 | 预期主要噪声源（fpr_note 已覆盖） |
|---|---|---|
| priv-suid-file-create | 0 | chmod 755 与 4755 不可区分（G11），生产=受监控文件的授权变更 |
| priv-ptrace-attach | 0 | 未白名单调试器（py-spy/delve），yama 已挡非 root |
| priv-kernel-module-load | 0 | 启动期/docker 按需加载（模块名白名单吸收） |
| priv-unshare-userns | 0 | rootless 容器/bwrap 沙箱 |
| persist-crontab-tamper | 0 | ansible/包安装写 /etc/cron.d/ |
| persist-systemd-unit-write | 0 | dpkg/rpm 落 unit |
| persist-ld-preload | 0 | 极少（正常系统无人写该文件） |
| persist-container-docker-exec | 0 | CI 构建容器（挂 docker.sock） |

## 收紧汇总

- 当场收紧 2 条（F1 cron comm 豁免、F2 apt-key comm 豁免），均为 D1 core 规则条件收窄，检出域只缩不扩（G8 无新增遮蔽）。
- 收紧后复跑 run_all.sh 22 用例 × 2 轮全 PASS（无回归）。
- F3 受 G1 限制不可收紧，F4 为 D1 既有取舍，均维持现状。
