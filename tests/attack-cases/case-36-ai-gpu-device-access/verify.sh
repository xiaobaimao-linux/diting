#!/bin/bash
# 用例 36 验证：ai-gpu-device-access 告警
# 预期：dsl.ai_gpu_device_access 告警 >=1（规则 AI Gpu Device Access）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-36-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.ai_gpu_device_access'")
[ "$n" -ge 1 ] && pass "非白名单进程访问 GPU 设备告警 ×$n" || fail "dsl.ai_gpu_device_access 告警只有 $n 次，预期 >=1"
exit $((n < 1))
