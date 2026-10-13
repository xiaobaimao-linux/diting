#!/bin/bash
# 攻击用例库批量执行：启动 monitor，30 个用例连跑 2 遍，输出 PASS/FAIL 汇总。
# 用法: sudo -n bash tests/attack-cases/run_all.sh        （需要 root：加载 eBPF + 部分攻击动作用 root）
# 退出码: 0 = 全部用例 × 2 轮 PASS；1 = 有失败项。
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="/tmp/bg-attack-cases"
LOG="${WORK_DIR}/monitor.log"
PIDFILE="${WORK_DIR}/monitor.pid"
ROUNDS=2

CASES="case-01-reverse-shell case-02-read-etc-shadow case-03-chmod-777 \
       case-04-docker-sock-container case-05-batch-sensitive-read case-06-container-mount-tamper \
       case-07-exec-reverse-shell-interpreter case-08-exec-reverse-shell-dualuse \
       case-09-exec-suspicious-tmp-binary case-10-exec-webspawner-shell \
       case-11-cred-read-shadow case-12-cred-write-passwd \
       case-13-cred-tamper-authorized-keys case-14-cred-clear-history \
       case-15-priv-suid-file-create case-16-priv-ptrace-attach \
       case-17-priv-kernel-module-load case-18-priv-unshare-userns \
       case-19-persist-crontab-tamper case-20-persist-systemd-unit-write \
       case-21-persist-ld-preload case-22-persist-container-docker-exec \
       case-23-mining-pool-port-connect case-24-mining-pool-dns \
       case-25-mining-binary-exec case-26-mining-shm-exec \
       case-27-evasion-clear-security-log case-28-evasion-stop-audit-service \
       case-29-evasion-chattr-immutable case-30-evasion-kill-security-tool"

cd "$ROOT_DIR"
mkdir -p "$WORK_DIR"
: > "$WORK_DIR/results.txt"

echo "=== 前置检查 ==="
if [ "$(id -u)" -ne 0 ]; then
    sudo -n true || { echo "FAIL: 无 sudo 凭据，请先 sudo -v 或用 sudo -S 喂密码"; exit 1; }
fi
[ -x "$ROOT_DIR/diting" ] || { echo "FAIL: diting 不存在"; exit 1; }
docker info >/dev/null 2>&1 || echo "WARN: docker 不可用，case-04/06 将失败"

echo "=== 准备用例文件 ==="
cat > "$WORK_DIR/chmod-target.conf" <<'EOF'
# 攻击用例库 chmod 测试目标
sensitive_option=true
EOF
cat > "$WORK_DIR/protected-baseline.conf" <<'EOF'
# diting 受保护基线文件（攻击用例库测试对象）
config_value=original
EOF
# W6 D1 凭据类用例的测试文件（必须在 monitor 启动前存在：inode 注册在启动时完成；
# 用例只做追加/截断，不删除重建，避免 inode 变化导致第 2 轮无事件）
cp /etc/passwd "$WORK_DIR/passwd-copy"
mkdir -p "$WORK_DIR/fakehome/.ssh"
cat > "$WORK_DIR/fakehome/.ssh/authorized_keys" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaselineGuardTestKeyOwner owner@test
EOF
cat > "$WORK_DIR/fakehome/.bash_history" <<'EOF'
ls -la
cat /etc/passwd
EOF
# W6 D2 提权/持久化类用例的测试替身（同样必须先于 monitor 启动创建；
# cleanup 用 cat > 原地覆盖恢复，内容与这里保持一致，避免 inode 变化）
cat > "$WORK_DIR/suid-target.conf" <<'EOF'
# 攻击用例库 SUID 测试目标
setuid_option=false
EOF
chmod 0644 "$WORK_DIR/suid-target.conf"
cat > "$WORK_DIR/crontab-copy" <<'EOF'
# 攻击用例库 crontab 替身（对应 /etc/crontab）
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 * * * * root cd / && run-parts --report /etc/cron.hourly
EOF
cat > "$WORK_DIR/unit-copy.service" <<'EOF'
# 攻击用例库 systemd unit 替身（对应 /etc/systemd/system/*.service）
[Unit]
Description=Baseline Guard Test Unit
[Service]
ExecStart=/bin/true
EOF
cat > "$WORK_DIR/ld.so.preload-copy" <<'EOF'
# 攻击用例库 ld.so.preload 替身（对应 /etc/ld.so.preload）
EOF
# W7 D3 防御规避类用例的测试替身（同样必须先于 monitor 启动创建：DSL 规则 file.path
# 字面量在加载期自动登记 inode，G6 已修复；cleanup 用 cat > 原地覆盖恢复，避免 inode 变化）
cat > "$WORK_DIR/auth.log-copy" <<'EOF'
Oct 12 00:00:01 host sshd[1000]: Server listening on 0.0.0.0 port 22.
EOF
printf 'reboot~test\n' > "$WORK_DIR/wtmp-copy"
# /root/.ssh/id_rsa 不存在时生成临时假密钥，cleanup 会删除
if [ ! -f /root/.ssh/id_rsa ]; then
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    ssh-keygen -t rsa -b 2048 -N '' -f /root/.ssh/id_rsa -q <<< y >/dev/null 2>&1
    touch /root/.ssh/.bg_attack_dummy_id_rsa
fi

echo "=== 启动 monitor ==="
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "已有 monitor 在跑（pid $(cat "$PIDFILE")），先停掉"
    kill -TERM "$(cat "$PIDFILE")" 2>/dev/null; sleep 2
fi
# 历史会话残留的 monitor 会同时消费事件、各自节流并落同一告警库，造成用例结果串扰
# （W6 D2 实测：残留实例只有旧规则集，把 dsl.persist_container_docker_exec 的命中抢成
#  示例规则 dsl.docker_cli_executed_inside_container，case-22 r2 假失败）
stale=$(pgrep -f "diting monitor" | grep -v "^$$\$" || true)
if [ -n "$stale" ]; then
    echo "发现残留 monitor 进程（$stale），先停掉避免告警串扰"
    kill -TERM $stale 2>/dev/null; sleep 2
    pgrep -f "diting monitor" >/dev/null && kill -KILL $stale 2>/dev/null
fi
if [ "$(id -u)" -eq 0 ]; then
    bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/diting' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/attack-cases/config.yaml'" >"$LOG" 2>&1 &
else
    sudo -n bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/diting' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/attack-cases/config.yaml'" >"$LOG" 2>&1 &
fi

ready=0
for i in $(seq 1 40); do
    grep -q "Monitoring started" "$LOG" && { ready=1; break; }
    grep -q "bpf_program_error\|service_stop" "$LOG" && break
    sleep 0.5
done
[ "$ready" -eq 1 ] || { echo "FAIL: monitor 未就绪，日志:"; tail -20 "$LOG"; exit 1; }
echo "monitor 就绪 (pid $(cat "$PIDFILE"))，探针模式: $(grep -o 'LSM (ring buffer)\|LSM (perf buffer)\|kprobe mode' "$LOG" | head -1)"

overall=0
for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "=== 第 $round 轮 ==="
    for c in $CASES; do
        name=$(basename "$c")
        tag="case-$(echo "$name" | cut -d- -f2)-r${round}"
        bash "tests/attack-cases/$c/run.sh" "$tag"
        out=$(bash "tests/attack-cases/$c/verify.sh" "$tag")
        echo "$out" | sed "s/^/[$name r$round] /"
        echo "[$name r$round] $out" | grep -o "PASS.*\|FAIL.*" >> "$WORK_DIR/results.txt"
        echo "[$name r$round] $out" | grep -q "FAIL" && overall=1
        bash "tests/attack-cases/$c/cleanup.sh" >/dev/null 2>&1
    done
    # throttle=10s，等它过期再跑下一轮，保证每轮告警都能落库
    [ "$round" -lt "$ROUNDS" ] && { echo "(等待 12s 让告警节流过期)"; sleep 12; }
done

echo ""
echo "=== 停止 monitor ==="
kill -TERM "$(cat "$PIDFILE")" 2>/dev/null
for i in $(seq 1 20); do
    kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break
    sleep 0.5
done
kill -0 "$(cat "$PIDFILE")" 2>/dev/null && { kill -KILL "$(cat "$PIDFILE")"; echo "WARN: monitor 未能优雅退出"; }
rm -f "$PIDFILE"

echo ""
echo "=== 清理临时假密钥 ==="
if [ -f /root/.ssh/.bg_attack_dummy_id_rsa ]; then
    rm -f /root/.ssh/id_rsa /root/.ssh/.bg_attack_dummy_id_rsa
    rmdir /root/.ssh 2>/dev/null
    echo "已删除 setup 生成的临时 /root/.ssh/id_rsa"
fi

echo ""
echo "=== 汇总 ==="
cat "$WORK_DIR/results.txt"
echo "monitor 日志: $LOG"
exit $overall
