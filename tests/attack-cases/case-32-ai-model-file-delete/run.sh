#!/bin/bash
# 用例 32 模型文件删除/改名：对替身 victim-rename.pt 执行 mv 改名
# （mv 保 inode——登记在启动期完成，改名后 inode 不变，cleanup 改回供下一轮；
#  不用 rm：删除后重建会产生新 inode，第 2 轮无事件，同 W6/W7 替身纪律）。
# AI 升级联动：事前注入 model_file 资产，告警应自动升级 high→critical。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-32-r1}"
mark_begin "$tag"

MODEL="$WORK_DIR/unmanaged/victim-rename.pt"
now=$(date +%Y-%m-%dT%H:%M:%S)
sqlite_run "$ALERTS_DB" "INSERT OR REPLACE INTO assets(asset_type,name,detail_json,first_seen,last_seen) VALUES('model_file','$MODEL','{\"source\":\"w8s2-case-32\"}','$now','$now');"

mv "$MODEL" "$MODEL.bak"
exit 0
