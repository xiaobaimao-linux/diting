#!/bin/bash
# 用例 21 篡改 ld.so.preload（测试替身）：安全约束下绝不写真实 /etc/ld.so.preload
# （写了会导致全系统动态链接加载恶意库，破坏性不可逆），改写
# /tmp/bg-attack-cases/ld.so.preload-copy（替身路径在规则 condition 列表内）
# 预期：alerts 出现 dsl.persist_ld_preload_tamper
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-21-r1}"
mark_begin "$tag"

echo "/tmp/.bg-backdoor/evil.so" >> "$WORK_DIR/ld.so.preload-copy"
exit 0
