#!/bin/bash
# 用例 20 清理：重写替身原始内容（cat > 原地覆盖保持同一 inode，与 run_all.sh setup 内容一致）
cat > /tmp/bg-attack-cases/unit-copy.service <<'EOF'
# 攻击用例库 systemd unit 替身（对应 /etc/systemd/system/*.service）
[Unit]
Description=Baseline Guard Test Unit
[Service]
ExecStart=/bin/true
EOF
exit 0
