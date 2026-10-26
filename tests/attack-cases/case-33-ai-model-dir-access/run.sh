#!/bin/bash
# 用例 33 模型目录访问：cat（comm=cat，非白名单）读受管目录替身
# /tmp/bg-attack-cases/models/ 下的 model.gguf——受管目录内模型文件的读取
# 归 ai-model-dir-access（ai-model-file-read 已按目录前缀显式剔除，G8 互斥）。
# AI 升级联动：事前注入 model_file 资产，告警应自动升级 medium→high。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-33-r1}"
mark_begin "$tag"

MODEL="$WORK_DIR/models/model.gguf"
now=$(date +%Y-%m-%dT%H:%M:%S)
sqlite_run "$ALERTS_DB" "INSERT OR REPLACE INTO assets(asset_type,name,detail_json,first_seen,last_seen) VALUES('model_file','$MODEL','{\"source\":\"w8s2-case-33\"}','$now','$now');"

cat "$MODEL" >/dev/null
exit 0
