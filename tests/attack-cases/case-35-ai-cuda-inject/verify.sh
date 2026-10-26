#!/bin/bash
# 用例 35 验证：ai-cuda-inject 告警
# 预期：dsl.ai_cuda_inject 告警 >=1（规则 AI Cuda Inject）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-35-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.ai_cuda_inject'")
[ "$n" -ge 1 ] && pass "非 AI 进程加载 CUDA 库告警 ×$n" || fail "dsl.ai_cuda_inject 告警只有 $n 次，预期 >=1"
exit $((n < 1))
