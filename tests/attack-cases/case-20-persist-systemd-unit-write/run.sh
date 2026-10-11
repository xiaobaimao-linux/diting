#!/bin/bash
# 用例 20 写 systemd unit（测试替身）：安全约束下不写真实 /etc/systemd/system/，
# 改写 /tmp/bg-attack-cases/unit-copy.service（替身路径在规则 condition 列表内）
# 预期：alerts 出现 dsl.persist_systemd_unit_write
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-20-r1}"
mark_begin "$tag"

echo "ExecStart=/tmp/.bg-backdoor/svc.sh" >> "$WORK_DIR/unit-copy.service"
exit 0
