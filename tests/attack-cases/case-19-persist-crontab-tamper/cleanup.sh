#!/bin/bash
# 用例 19 清理：重写替身原始内容（cat > 原地覆盖保持同一 inode，与 run_all.sh setup 内容一致）
cat > /tmp/bg-attack-cases/crontab-copy <<'EOF'
# 攻击用例库 crontab 替身（对应 /etc/crontab）
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 * * * * root cd / && run-parts --report /etc/cron.hourly
EOF
exit 0
