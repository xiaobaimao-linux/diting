#!/bin/bash
# 用例 22 容器内执行 docker 客户端（逃逸前置）：与 case-04 同一攻击动作，
# 验证对象是 DSL 规则 dsl.persist_container_docker_exec（case-04 验证遥测事件，本条验证规则告警）
# 优先用官方 docker 镜像；拉取失败时降级为 diting:dev 挂载宿主机 docker 客户端
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-22-r1}"
mark_begin "$tag"

run_in_docker_image() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        docker sh -c "docker ps" >/dev/null 2>&1
}

run_fallback() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v /usr/bin/docker:/usr/bin/docker:ro \
        -e HOME=/tmp \
        --entrypoint docker \
        diting:dev ps >/dev/null 2>&1
}

if docker image inspect docker >/dev/null 2>&1; then
    run_in_docker_image
elif docker pull docker >/dev/null 2>&1; then
    run_in_docker_image
else
    echo "WARN: docker 镜像不可用，降级为 diting:dev + 挂载宿主机 docker 客户端" >&2
    run_fallback
fi
exit 0
