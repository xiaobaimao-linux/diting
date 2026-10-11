#!/bin/bash
# 用例 16 非白名单进程 ptrace attach：python3（非调试器白名单）对 sleep 进程
# PTRACE_ATTACH 后立即 DETACH（root 下运行，yama ptrace_scope=1 不挡 CAP_SYS_PTRACE）
# 预期：alerts 出现 dsl.priv_ptrace_attach
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-16-r1}"
mark_begin "$tag"

sleep 300 &
echo $! > "$WORK_DIR/ptrace-sleep.pid"
sleep_pid=$(cat "$WORK_DIR/ptrace-sleep.pid")

python3 - "$sleep_pid" <<'EOF'
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
pid = int(sys.argv[1])
rc = libc.ptrace(ctypes.c_ulong(16), ctypes.c_ulong(pid), None, None)  # PTRACE_ATTACH
if rc != 0:
    print(f"WARN: PTRACE_ATTACH 失败 rc={rc} errno={ctypes.get_errno()}", file=sys.stderr)
    sys.exit(0)  # 不阻断用例流，verify 会报失败
libc.ptrace(ctypes.c_ulong(17), ctypes.c_ulong(pid), None, None)       # PTRACE_DETACH
EOF
exit 0
