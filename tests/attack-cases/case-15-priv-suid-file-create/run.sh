#!/bin/bash
# 用例 15 chmod 设置 SUID 位（测试替身）：安全约束下不碰真实系统二进制，
# 改对 /tmp/bg-attack-cases/suid-target.conf 执行 chmod 4755
# （file.new_mode 渲染 &0777 掩掉高位，04755 渲染为 0755，见 docs/rule-engine-gaps.md G11）
# 预期：alerts 出现 dsl.priv_suid_file_create
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-15-r1}"
mark_begin "$tag"

chmod 4755 "$WORK_DIR/suid-target.conf"
exit 0
