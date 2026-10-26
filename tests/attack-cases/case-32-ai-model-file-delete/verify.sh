#!/bin/bash
# 用例 32 验证：ai-model-file-delete 告警 + AI 升级联动双重断言
# 预期：dsl.ai_model_file_delete ≥1，且至少 1 条 escalated=1 且
# severity='critical'（升后值写死）且 severity_origin='high'（升前值写死）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-32-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.ai_model_file_delete'")
esc=$(count_alerts_since "$tag" "rule_id='dsl.ai_model_file_delete' and escalated=1 and severity='critical' and severity_origin='high'")
if [ "$n" -ge 1 ] && [ "$esc" -ge 1 ]; then
    pass "模型文件删除/改名告警 ×$n，AI 升级联动(high→critical) ×$esc"
    exit 0
fi
fail "dsl.ai_model_file_delete 告警 $n 次、升级联动 $esc 次，预期均 >=1"
exit 1
