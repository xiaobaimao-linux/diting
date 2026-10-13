#!/bin/bash
# 用例 25 验证：挖矿二进制执行
# 预期：dsl.mining_binary_exec 告警 >=1（规则 Mining Binary Exec）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-25-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.mining_binary_exec'")
[ "$n" -ge 1 ] && pass "挖矿二进制执行告警 ×$n" || fail "dsl.mining_binary_exec 告警只有 $n 次，预期 >=1"
exit $((n < 1))
