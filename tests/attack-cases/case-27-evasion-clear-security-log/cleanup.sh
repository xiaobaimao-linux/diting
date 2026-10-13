#!/bin/bash
# 用例 27 清理：原地覆盖恢复初始内容（保 inode，与 run_all.sh setup 一致），供下一轮使用
cat > /tmp/bg-attack-cases/auth.log-copy <<'EOF'
Oct 12 00:00:01 host sshd[1000]: Server listening on 0.0.0.0 port 22.
EOF
printf 'reboot~test\n' > /tmp/bg-attack-cases/wtmp-copy
exit 0
