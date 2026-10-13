#!/bin/bash
# 用例 29 清理：解锁并保留文件（第 2 轮 +i 前先已是 -i 状态，chattr +i 可重复执行）
chattr -i /tmp/bg-attack-cases/chattr-target.conf 2>/dev/null
exit 0
