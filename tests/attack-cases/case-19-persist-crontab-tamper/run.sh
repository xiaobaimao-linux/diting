#!/bin/bash
# 用例 19 篡改 crontab（测试替身）：安全约束下不写真实 /etc/crontab，
# 改写 /tmp/bg-attack-cases/crontab-copy（替身路径在规则 condition 列表内，选型理由同 D1 case-12）
# 追加写是真实 write(2)，能产生 file.write 事件（G9）
# 预期：alerts 出现 dsl.persist_crontab_tamper
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-19-r1}"
mark_begin "$tag"

echo "* * * * * root /tmp/.bg-backdoor/cron.sh" >> "$WORK_DIR/crontab-copy"
exit 0
