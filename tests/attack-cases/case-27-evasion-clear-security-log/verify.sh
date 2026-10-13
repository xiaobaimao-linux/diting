#!/bin/bash
# 用例 27 验证：清空安全日志
# 预期：dsl.evasion_clear_security_log 告警 >=1（写入者 bash 不在日志系统白名单）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-27-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.evasion_clear_security_log'")
[ "$n" -ge 1 ] && pass "安全日志篡改告警 ×$n" || fail "dsl.evasion_clear_security_log 告警只有 $n 次，预期 >=1"
exit $((n < 1))
