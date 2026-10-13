#!/bin/bash
# 用例 28 停审计服务：systemctl 指向 auditd 的调用
# G19 退化说明：exec 无 cmdline，规则退化为"systemctl 被执行即报"，无法区分 status/stop——
# 因此本用例用非破坏性的 `systemctl is-active auditd` 触发（等价命中路径），
# 禁止真停 auditd/rsyslog（会破坏宿主机审计与日志）。
# sudo 前缀场景说明：run_all 整体以 root 跑；规则判定看最终执行的 systemctl 本体 exe，
# 与是否经 sudo 无关（exe 富化取 exec 目标）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-28-r1}"
mark_begin "$tag"

systemctl is-active auditd >/dev/null 2>&1
systemctl is-enabled rsyslog >/dev/null 2>&1
exit 0
