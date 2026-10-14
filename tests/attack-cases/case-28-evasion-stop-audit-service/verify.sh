#!/bin/bash
# 用例 28 验证：停/禁审计服务（W8 G19 修复后：cmdline 动作+目标判定路径）
# 预期：dsl.evasion_stop_audit_service 告警 >=1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-28-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.evasion_stop_audit_service'")
[ "$n" -ge 1 ] && pass "停/禁审计服务告警 ×$n" || fail "dsl.evasion_stop_audit_service 告警只有 $n 次，预期 >=1"
exit $((n < 1))
