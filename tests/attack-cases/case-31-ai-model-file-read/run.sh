#!/bin/bash
# 用例 31 非白名单进程读模型文件：cat（comm=cat，不在 python*/推理框架白名单）读
# 受管目录之外的替身模型文件 unmanaged/victim-read.safetensors
# （受管目录内的读取归 ai-model-dir-access，两规则按目录前缀显式互斥，G8）。
# AI 升级联动：事前把替身路径写入 assets 表（model_file，last_seen 取当前时间），
# 告警应被 W6 D4 机制命中模型资产自动升级 medium→high。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-31-r1}"
mark_begin "$tag"

MODEL="$WORK_DIR/unmanaged/victim-read.safetensors"
now=$(date +%Y-%m-%dT%H:%M:%S)
sqlite_run "$ALERTS_DB" "INSERT OR REPLACE INTO assets(asset_type,name,detail_json,first_seen,last_seen) VALUES('model_file','$MODEL','{\"source\":\"w8s2-case-31\"}','$now','$now');"

cat "$MODEL" >/dev/null
exit 0
