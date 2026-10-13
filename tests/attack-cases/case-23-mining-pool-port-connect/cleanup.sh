#!/bin/bash
# 用例 23 清理：杀掉残留的 python 监听
pkill -f "bind(('127.0.0.1', 3333))" 2>/dev/null
exit 0
