#!/bin/bash
# 用例 30 杀安全工具：pkill 指向伪装成安全工具的替身进程（falco 命名的 sleep 副本）
# 替身选址 $WORK_DIR（tmp 规则会顺带告警该 exec，属预期副告警、与本用例断言无关）；
# 禁止杀真实安全进程（含本项目 monitor）。
# G19 退化说明：规则看不到 pkill 的目标名，命中的是 pkill 的 exec 事件本身。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-30-r1}"
mark_begin "$tag"

cp /bin/sleep "$WORK_DIR/falco"
"$WORK_DIR/falco" 60 &
sleep 0.3
pkill -f "bg-attack-cases/falco" 2>/dev/null
exit 0
