#!/bin/bash
# 用例 23 验证：矿池端口外联
# 预期：dsl.mining_pool_port_connect 告警 >=1（规则 Mining Pool Port Connect）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-23-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.mining_pool_port_connect'")
[ "$n" -ge 1 ] && pass "矿池端口外联告警 ×$n" || fail "dsl.mining_pool_port_connect 告警只有 $n 次，预期 >=1"
exit $((n < 1))
