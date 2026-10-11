#!/bin/bash
# 用例 22 验证：容器内执行 docker 客户端规则
# 预期：dsl.persist_container_docker_exec 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-22-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.persist_container_docker_exec'")
[ "$n" -ge 1 ] && pass "容器内 docker exec 告警 ×$n" || fail "dsl.persist_container_docker_exec 告警只有 $n 次，预期 >=1"
exit $((n < 1))
