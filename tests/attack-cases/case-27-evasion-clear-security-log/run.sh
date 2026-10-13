#!/bin/bash
# 用例 27 清空安全日志：追加写 + 删重建 替身日志文件（沿用 W6 替身机制，禁动真实 /var/log）
# 替身 auth.log-copy / wtmp-copy 由 run_all.sh 在 monitor 启动前创建（inode 注册在启动/加载期完成，
# DSL 规则 file.path 字面量自动登记，G6 已修复）。
# 注意 G9：truncate/cp /dev/null 不产生 file.write，追加写用 echo >>（真实 write(2) 字节）；
# unlink 路径用"改名再删"回避？——不需要：file.unlink 事件与 inode 注册无关（删除已注册 inode
# 本身即事件），但删除后第 2 轮文件不存在、追加写会换 inode——故 cleanup 必须原地重建同内容文件
# 并在第 2 轮依赖 monitor 仍持有旧 inode？不行。取舍：本用例只测追加写（write 路径），
# 不删文件，保证两轮 inode 稳定；unlink 路径由规则 condition 的 in (file.write, file.unlink) 声明，
# 删除触发面与 cred-clear-history 等既有规则同款、已被 case-13/14 的机制覆盖验证。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-27-r1}"
mark_begin "$tag"

echo 'Oct 12 03:00:01 host sshd[6666]: Accepted password for root from 10.0.0.9' >> "$WORK_DIR/auth.log-copy"
printf 'utmp-wipe-sim\r\n' >> "$WORK_DIR/wtmp-copy"
exit 0
