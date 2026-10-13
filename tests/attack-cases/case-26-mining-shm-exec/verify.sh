#!/bin/bash
# 用例 26 验证：/dev/shm 执行
# 预期：dsl.mining_shm_exec 告警 >=1；且不误落 dsl.exec_suspicious_tmp_binary（命中域互斥自查）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-26-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.mining_shm_exec'")
m=$(count_alerts_since "$tag" "rule_id='dsl.exec_suspicious_tmp_binary'")
if [ "$n" -ge 1 ] && [ "$m" -eq 0 ]; then
    pass "shm 执行告警 ×$n（tmp 规则 $m，命中域互斥正确）"
else
    [ "$n" -lt 1 ] && fail "dsl.mining_shm_exec 告警只有 $n 次，预期 >=1"
    [ "$m" -gt 0 ] && fail "命中错落到 dsl.exec_suspicious_tmp_binary ×$m，命中域划分失效"
fi
exit $((n < 1 || m > 0))
