#!/bin/bash
# 用例 17 验证：内核模块加载规则
# 预期：dsl.priv_kernel_module_load 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-17-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.priv_kernel_module_load'")
[ "$n" -ge 1 ] && pass "内核模块加载告警 ×$n" || fail "dsl.priv_kernel_module_load 告警只有 $n 次，预期 >=1"
exit $((n < 1))
