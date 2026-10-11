#!/bin/bash
# 用例 19 验证：crontab 篡改规则
# 预期：dsl.persist_crontab_tamper 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-19-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.persist_crontab_tamper'")
[ "$n" -ge 1 ] && pass "crontab 篡改告警 ×$n" || fail "dsl.persist_crontab_tamper 告警只有 $n 次，预期 >=1"
exit $((n < 1))
