#!/bin/bash
# 用例 20 验证：systemd unit 写入规则
# 预期：dsl.persist_systemd_unit_write 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-20-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.persist_systemd_unit_write'")
[ "$n" -ge 1 ] && pass "systemd unit 写入告警 ×$n" || fail "dsl.persist_systemd_unit_write 告警只有 $n 次，预期 >=1"
exit $((n < 1))
