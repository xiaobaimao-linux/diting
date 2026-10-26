#!/bin/bash
# 用例 35 非 AI 进程加载 CUDA 库：cat（comm=cat，非白名单）读 CUDA 库替身
# /tmp/bg-attack-cases/fakelib/libcuda.so.1（真实库路径在无 GPU 机器上不存在，
# 加载期 warn 降级 G18，替身路径验证命中链路；替身随 run_all.sh setup 创建）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-35-r1}"
mark_begin "$tag"

cat "$WORK_DIR/fakelib/libcuda.so.1" >/dev/null
exit 0
