#!/bin/bash
# 用例 31 验证：ai-model-file-read 告警 + AI 升级联动双重断言
# 预期：dsl.ai_model_file_read ≥1，且至少 1 条 escalated=1 且 severity='high'（升后值写死）
# 且 severity_origin='medium'（升前值写死）——防"escalated 置位但级别未变"的假联动。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-31-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.ai_model_file_read'")
esc=$(count_alerts_since "$tag" "rule_id='dsl.ai_model_file_read' and escalated=1 and severity='high' and severity_origin='medium'")
if [ "$n" -ge 1 ] && [ "$esc" -ge 1 ]; then
    pass "模型文件读取告警 ×$n，AI 升级联动(medium→high) ×$esc"
    exit 0
fi
fail "dsl.ai_model_file_read 告警 $n 次、升级联动 $esc 次，预期均 >=1"
exit 1
