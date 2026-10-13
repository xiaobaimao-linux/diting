#!/bin/bash
# 用例 29 验证：chattr 锁定
# 预期：dsl.evasion_chattr_immutable 告警 >=1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-29-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.evasion_chattr_immutable'")
[ "$n" -ge 1 ] && pass "chattr 执行告警 ×$n" || fail "dsl.evasion_chattr_immutable 告警只有 $n 次，预期 >=1"
exit $((n < 1))
