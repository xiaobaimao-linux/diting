#!/bin/bash
# 用例 15 验证：SUID 位设置规则
# 预期：dsl.priv_suid_file_create 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-15-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.priv_suid_file_create'")
[ "$n" -ge 1 ] && pass "SUID 位设置告警 ×$n" || fail "dsl.priv_suid_file_create 告警只有 $n 次，预期 >=1"
exit $((n < 1))
