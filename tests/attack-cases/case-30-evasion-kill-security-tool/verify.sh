#!/bin/bash
# 用例 30 验证：杀安全工具
# 预期：dsl.evasion_kill_security_tool 告警 >=1（pkill exec 命中）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-30-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.evasion_kill_security_tool'")
[ "$n" -ge 1 ] && pass "kill 家族执行告警 ×$n" || fail "dsl.evasion_kill_security_tool 告警只有 $n 次，预期 >=1"
exit $((n < 1))
