#!/bin/bash
# 用例 18 unshare 创建 user namespace：unshare --user（CLONE_NEWUSER=0x10000000，
# ns.flags 数值判定，ns.names 命名与文档不符见 docs/rule-engine-gaps.md G10）
# 预期：alerts 出现 dsl.priv_unshare_user_namespace
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-18-r1}"
mark_begin "$tag"

unshare --user true || echo "WARN: unshare --user 失败" >&2
exit 0
