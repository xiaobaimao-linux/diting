#!/bin/bash
# 用例 33 验证：ai-model-dir-access 告警 + AI 升级联动双重断言
# 预期：dsl.ai_model_dir_access ≥1，且至少 1 条 escalated=1 且
# severity='high'（升后值写死）且 severity_origin='medium'（升前值写死）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-33-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.ai_model_dir_access'")
esc=$(count_alerts_since "$tag" "rule_id='dsl.ai_model_dir_access' and escalated=1 and severity='high' and severity_origin='medium'")
if [ "$n" -ge 1 ] && [ "$esc" -ge 1 ]; then
    pass "模型目录访问告警 ×$n，AI 升级联动(medium→high) ×$esc"
    exit 0
fi
fail "dsl.ai_model_dir_access 告警 $n 次、升级联动 $esc 次，预期均 >=1"
exit 1
