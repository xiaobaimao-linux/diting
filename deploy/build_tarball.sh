#!/bin/bash
# build_tarball.sh — 产出 diting 预编译安装包（tarball）
# 用法：
#   本机直出：        bash deploy/build_tarball.sh
#   指定目标系统容器：docker run --rm -v $PWD:/src:ro -v $PWD/dist:/out ubuntu:22.04 bash -c \
#       'cp -r /src /build && cd /build && apt-get update -qq && \
#        apt-get install -y -qq build-essential clang linux-tools-generic libelf-dev zlib1g-dev \
#        libssl-dev libfmt-dev libyaml-cpp-dev libsqlite3-dev libcurl4-openssl-dev ca-certificates >/dev/null && \
#        bash deploy/build_tarball.sh && cp dist/*.tar.gz /out/'
# 产物：dist/diting-<版本>-<os-tag>-x86_64.tar.gz（含 install.sh，解压即装）
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# 容器内 linux-tools 的 /usr/sbin/bpftool 是按 uname -r 分发的 shim，宿主内核
# 无匹配 linux-tools-<ver> 包时 shim 失效；直接链接已安装的真实二进制兜底
if ! bpftool version >/dev/null 2>&1; then
    REAL_BPFTOOL=$(ls /usr/lib/linux-tools-*/bpftool 2>/dev/null | head -1)
    [ -n "$REAL_BPFTOOL" ] && ln -sf "$REAL_BPFTOOL" /usr/local/bin/bpftool
fi

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo v1.0.0)}"
# OS 标签：/etc/os-release 的 ID-VERSION_ID（如 ubuntu-22.04），容器内构建保证 ABI 对口
OS_TAG="$(. /etc/os-release && echo "${ID}-${VERSION_ID}")"
[ -n "$OS_TAG" ] || OS_TAG="unknown-os"

PKG="diting-${VERSION}-${OS_TAG}-x86_64"
STAGE="dist/$PKG"

echo "=== build tarball: $PKG ==="
make clean >/dev/null 2>&1 || true
make -j"$(nproc)"

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/deploy" "$STAGE/config" "$STAGE/rules" "$STAGE/cis"

install -s -m 755 diting "$STAGE/bin/diting"   # strip：发行包不带调试符号（47MB→~6MB）
install -m 755 install.sh "$STAGE/install.sh"
install -m 644 deploy/monitor.yaml "$STAGE/deploy/monitor.yaml"
install -m 644 deploy/diting.service "$STAGE/deploy/diting.service"
install -m 644 baselines/default.yaml "$STAGE/config/check.yaml"
install -m 644 cis/cis-baseline-v1.yaml "$STAGE/cis/cis-baseline-v1.yaml"
cp -r rules/core rules/examples "$STAGE/rules/"

tar czf "dist/$PKG.tar.gz" -C dist "$PKG"
echo "=== 产物: dist/$PKG.tar.gz ==="
tar tzf "dist/$PKG.tar.gz" | head -5
echo "..."
du -h "dist/$PKG.tar.gz"
