#!/bin/bash
# 用例 30 清理：确保替身进程死亡、删替身文件
pkill -f "bg-attack-cases/falco" 2>/dev/null
rm -f /tmp/bg-attack-cases/falco
exit 0
