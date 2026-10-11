#!/bin/bash
# 用例 16 验证：ptrace attach 规则
# 预期：dsl.priv_ptrace_attach 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-16-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.priv_ptrace_attach'")
[ "$n" -ge 1 ] && pass "ptrace attach 告警 ×$n" || fail "dsl.priv_ptrace_attach 告警只有 $n 次，预期 >=1"
exit $((n < 1))
