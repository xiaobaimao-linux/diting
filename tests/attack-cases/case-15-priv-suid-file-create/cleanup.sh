#!/bin/bash
# 用例 15 清理：恢复替身文件权限为 0644（不换 inode）
chmod 0644 /tmp/bg-attack-cases/suid-target.conf 2>/dev/null
exit 0
