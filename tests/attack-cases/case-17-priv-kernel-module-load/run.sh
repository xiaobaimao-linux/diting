#!/bin/bash
# 用例 17 加载内核模块：modprobe dummy（可逆，cleanup 卸载；dummy 不在规则白名单内）
# 预期：alerts 出现 dsl.priv_kernel_module_load
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-17-r1}"
mark_begin "$tag"

modprobe -r dummy 2>/dev/null   # 已加载则先卸，保证本次 load 产生新的 module_load 事件
modprobe dummy || echo "WARN: modprobe dummy 失败" >&2
exit 0
