#!/bin/bash
# 用例 32 清理：把改名后的替身改回原名（保 inode），删除注入的资产行
source "$(dirname "$0")/../lib.sh"
[ -f "$WORK_DIR/unmanaged/victim-rename.pt.bak" ] && mv -f "$WORK_DIR/unmanaged/victim-rename.pt.bak" "$WORK_DIR/unmanaged/victim-rename.pt"
sqlite_run "$ALERTS_DB" "DELETE FROM assets WHERE asset_type='model_file' AND name='$WORK_DIR/unmanaged/victim-rename.pt';"
exit 0
