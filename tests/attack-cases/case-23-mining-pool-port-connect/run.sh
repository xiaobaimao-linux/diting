#!/bin/bash
# 用例 23 矿池端口外联：连接本地 127.0.0.1:3333（stratum 常见端口）
# 安全约束：禁止真实连接外部矿池——只连本地回环上的监听端。
# 选型记录：规则 condition 选"端口匹配不强制外网 IP"（而非加测试模式）——
# DSL v1 无测试模式/宏；且回环白名单会放行"本地代理跳板到矿池"的真实路径，
# 3333 族端口作目的端口的合法服务极少，端口即强信号（详见规则 desc/fpr_note）。
# 注意：监听端与连接端都用 python（不用 nc），避免 nc 的 exec 触发
# exec-reverse-shell-dualuse 规则、10s 节流窗口内干扰相邻用例（同 case-07 考量）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-23-r1}"
mark_begin "$tag"

PORT=3333
python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT))
s.listen(1)
s.settimeout(8)
try:
    conn, _ = s.accept()
    conn.recv(64)
except socket.timeout:
    pass
" >/dev/null 2>&1 &
L_PID=$!
sleep 0.5
timeout 5 python3 -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', $PORT))
s.send(b'{\"id\":1,\"method\":\"mining.subscribe\"}\n')
" >/dev/null 2>&1
kill $L_PID 2>/dev/null
exit 0
