#!/bin/bash
# 用例 21 验证：ld.so.preload 篡改规则
# 预期：dsl.persist_ld_preload_tamper 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-21-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.persist_ld_preload_tamper'")
[ "$n" -ge 1 ] && pass "ld.so.preload 篡改告警 ×$n" || fail "dsl.persist_ld_preload_tamper 告警只有 $n 次，预期 >=1"
exit $((n < 1))
