#!/bin/bash
# 用例 26 /dev/shm 执行：从 shm 启动无扩展名替身二进制
# 替身名 bgminer（无扩展名、非隐藏文件——隐藏文件含 . 受 G4 限制不命中，见规则 fpr_note）。
# W7 D3 起 /dev/shm 命中域归 mining-shm-exec 独占（exec-suspicious-tmp-binary 已收窄），
# 本用例同时回归该划分：断言命中的是 mining-shm-exec 而不是 tmp 规则。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-26-r1}"
mark_begin "$tag"

cp /bin/sleep /dev/shm/bgminer
/dev/shm/bgminer 3 >/dev/null 2>&1
exit 0
