#!/bin/bash
# 用例 29 chattr 锁定：chattr +i 锁定测试文件
# G19 退化说明：规则不区分 +i/-i（cmdline 不可见），用例用 +i（真实攻击动作）触发，
# cleanup 负责 -i 解锁。目标文件放在 $WORK_DIR（不动系统文件）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-29-r1}"
mark_begin "$tag"

touch "$WORK_DIR/chattr-target.conf"
chattr +i "$WORK_DIR/chattr-target.conf" 2>/dev/null
exit 0
