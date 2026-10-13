#!/bin/bash
# 用例 24 矿池域名解析：dig 含矿池关键字的无效域名（无需真实解析成功，查询事件含域名即可）
# 域名选型：pool-test.minergate.example.invalid——带 minergate 厂商关键字；
# 不用裸 pool-test.example.invalid，因为规则刻意不收 "pool."（pool.ntp.org 高频误报，
# 见规则 desc）。.invalid TLD（RFC 2606）保证不产生真实外部依赖外的歧义解析。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-24-r1}"
mark_begin "$tag"

dig +time=2 +tries=1 pool-test.minergate.example.invalid >/dev/null 2>&1
exit 0
