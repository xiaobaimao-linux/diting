#!/bin/bash
# 用例 36 非白名单进程访问 GPU 设备：cat（comm=cat，非白名单）读设备替身
# /tmp/bg-attack-cases/dev/nvidia0（本机无 GPU，真实 /dev/nvidia* 不存在，
# 加载期 warn 降级 G18，替身路径验证命中链路；替身随 run_all.sh setup 创建）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-36-r1}"
mark_begin "$tag"

cat "$WORK_DIR/dev/nvidia0" >/dev/null
exit 0
