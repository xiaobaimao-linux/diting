#!/bin/bash
# 用例 16 清理：杀掉 ptrace 目标 sleep 进程
if [ -f /tmp/bg-attack-cases/ptrace-sleep.pid ]; then
    kill "$(cat /tmp/bg-attack-cases/ptrace-sleep.pid)" 2>/dev/null
    rm -f /tmp/bg-attack-cases/ptrace-sleep.pid
fi
exit 0
