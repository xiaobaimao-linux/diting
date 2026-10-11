#!/bin/bash
# 用例 21 清理：重写替身原始内容（cat > 原地覆盖保持同一 inode，与 run_all.sh setup 内容一致）
cat > /tmp/bg-attack-cases/ld.so.preload-copy <<'EOF'
# 攻击用例库 ld.so.preload 替身（对应 /etc/ld.so.preload）
EOF
exit 0
