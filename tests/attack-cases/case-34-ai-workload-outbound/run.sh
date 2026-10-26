#!/bin/bash
# 用例 34 AI 工作负载外连：AI 运行时进程（comm=python3）连接本机外网口地址
# （hostname -I 首地址，如 192.168.x.x——本机地址经 local 路由表投递，流量不出网卡，
#  满足"禁真实外连"约束；回环 127.0.0.1 已被规则豁免，无法用回环触发）。
# 负面对照：同一监听端口上的回环连接不应产生告警（验证回环豁免不是空话）。
# 监听/连接都用 python3（同 case-23 考量：避免 nc exec 触发 dualuse 规则串扰）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-34-r1}"
mark_begin "$tag"

HOST_IP=$(hostname -I | awk '{print $1}')
PORT=8443

python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $PORT))
s.listen(2)
s.settimeout(8)
for _ in range(2):
    try:
        conn, _ = s.accept()
        conn.recv(64)
        conn.close()
    except socket.timeout:
        break
" >/dev/null 2>&1 &
L_PID=$!
sleep 0.5

# 攻击动作：AI 运行时 → 本机外网口地址（非回环 dip，应命中）
timeout 5 python3 -c "
import socket
s = socket.socket()
s.connect(('$HOST_IP', $PORT))
s.send(b'{\"weights\":\"chunk-0\"}\n')
" >/dev/null 2>&1

# 负面对照：AI 运行时 → 回环（规则已豁免 127.0.0.1，不应命中）
timeout 5 python3 -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', $PORT))
s.send(b'local-health-check\n')
" >/dev/null 2>&1

kill $L_PID 2>/dev/null
exit 0
