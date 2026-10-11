#!/bin/bash
# 用例 18 验证：user namespace 创建规则
# 预期：dsl.priv_unshare_user_namespace 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-18-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.priv_unshare_user_namespace'")
[ "$n" -ge 1 ] && pass "user namespace 创建告警 ×$n" || fail "dsl.priv_unshare_user_namespace 告警只有 $n 次，预期 >=1"
exit $((n < 1))
