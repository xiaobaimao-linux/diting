#!/bin/bash
# 用例 31 清理：删除注入的 model_file 资产行（替身文件保留，inode 不变，供下一轮）
source "$(dirname "$0")/../lib.sh"
sqlite_run "$ALERTS_DB" "DELETE FROM assets WHERE asset_type='model_file' AND name='$WORK_DIR/unmanaged/victim-read.safetensors';"
exit 0
