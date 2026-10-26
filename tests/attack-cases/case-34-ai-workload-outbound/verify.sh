#!/bin/bash
# 用例 34 验证：ai-workload-outbound 告警 + 回环豁免负面对照
# 预期：dsl.ai_workload_outbound ≥1（本机外网口地址连接），
# 且其中 dip=127.0.0.1 的告警 =0（回环豁免生效，output 模板含 dip 可直接断言）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-34-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.ai_workload_outbound'")
lb=$(count_alerts_since "$tag" "rule_id='dsl.ai_workload_outbound' and actual like '%dip=127.0.0.1%'")
if [ "$n" -ge 1 ] && [ "$lb" -eq 0 ]; then
    pass "AI 工作负载外连告警 ×$n，回环豁免 0 误命中"
    exit 0
fi
fail "dsl.ai_workload_outbound 告警 $n 次（预期 >=1）、回环误命中 $lb 次（预期 0）"
exit 1
