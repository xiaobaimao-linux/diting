#!/bin/bash
# 用例 25 挖矿二进制执行：以矿机名（xmrig）命名的替身二进制被执行
# 替身选址 /opt/bg-attack-cases/ 而非 /tmp：/tmp 下无扩展名执行会命中先加载的
# exec-suspicious-tmp-binary（单命中 G8，exec-ta0002 先于 mining-ta0040 加载），
# 归属不到 mining-binary-exec；用 /opt 验证"任意落盘位置 + 矿机名"的命中路径。
# 替身本体是 /bin/sleep 副本，无任何挖矿行为。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-25-r1}"
mark_begin "$tag"

mkdir -p /opt/bg-attack-cases
cp /bin/sleep /opt/bg-attack-cases/xmrig
/opt/bg-attack-cases/xmrig 3 >/dev/null 2>&1
exit 0
