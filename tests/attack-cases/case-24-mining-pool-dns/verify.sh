#!/bin/bash
# 用例 24 验证：矿池域名解析
# 预期：dsl.mining_pool_dns_query 告警 >=1（规则 Mining Pool Dns Query）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-24-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.mining_pool_dns_query'")
[ "$n" -ge 1 ] && pass "矿池域名解析告警 ×$n" || fail "dsl.mining_pool_dns_query 告警只有 $n 次，预期 >=1"
exit $((n < 1))
