#!/bin/bash
# 用例 28 停审计服务：systemctl 对审计服务的 stop/disable
# W8（2026-10-14）G19 已修复：exec 采集 cmdline，规则按"动作(stop/disable)+目标(auditd/rsyslog)"
# 精确判定，不再退化。禁止真停 auditd/rsyslog（会破坏宿主机审计与日志）——
# 本用例用不存在的假单元名触发同一命中路径（cmdline 含 stop/disable 与 auditd/rsyslog，
# systemctl 报"单元不存在"安全失败，无副作用）。
# sudo 前缀场景说明：run_all 整体以 root 跑；规则判定看最终执行的 systemctl 本体 exe
# 与其 argv（cmdline），与是否经 sudo 无关。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-28-r1}"
mark_begin "$tag"

systemctl stop auditd-case28-fakeunit >/dev/null 2>&1
systemctl disable rsyslog-case28-fakeunit >/dev/null 2>&1
exit 0
