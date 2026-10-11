#!/bin/bash
# 用例 17 清理：卸载 dummy 模块（可逆回滚）
modprobe -r dummy 2>/dev/null
exit 0
