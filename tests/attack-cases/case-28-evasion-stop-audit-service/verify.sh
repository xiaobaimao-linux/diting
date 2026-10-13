#!/bin/bash
# 用例 28 验证：停审计服务（G19 退化规则，exe 命中路径）
# 预期：dsl.evasion_stop_audit_service 告警 >=1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-28-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.evasion_stop_audit_service'")
[ "$n" -ge 1 ] && pass "systemctl 执行告警 ×$n" || fail "dsl.evasion_stop_audit_service 告警只有 $n 次，预期 >=1"
exit $((n < 1))
