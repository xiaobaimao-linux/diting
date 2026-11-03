#!/bin/bash
# install.sh — diting 安装脚本
# 路径：预编译包（bin/diting 在场）直接安装；否则源码全量编译兜底。
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== diting installer ==="

# ---------- 前置检测：缺什么报什么，报完统一退出非零 ----------
fail=0
err() { echo "ERROR: $1"; fail=1; }

# 1) root 或 sudo
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        err "需要 root 权限或 sudo，当前用户 $(id -un) 均无"
    fi
else
    SUDO=""
fi

# 2) 内核 >= 5.8（ring buffer 与遥测依赖；5.4~5.7 降级路径不在安装支持范围）
KMAJ=$(uname -r | cut -d. -f1)
KMIN=$(uname -r | cut -d. -f2)
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 8 ]; }; then
    err "内核需 >= 5.8，当前 $(uname -r)"
fi

# 3) BPF_LSM：可判定时缺失即报错；容器等无法判定的环境只告警不拦截
if [ -f "/boot/config-$(uname -r)" ]; then
    grep -q "CONFIG_BPF_LSM=y" "/boot/config-$(uname -r)" || \
        err "CONFIG_BPF_LSM 未启用（/boot/config-$(uname -r)），monitor 无法加载 LSM 探针"
elif [ -r /sys/kernel/security/lsm ]; then
    grep -qw bpf /sys/kernel/security/lsm || \
        err "BPF_LSM 未启用（/sys/kernel/security/lsm 无 bpf）"
else
    echo "WARN: 无法判定 BPF_LSM（容器环境？），继续安装；若 monitor 启动失败请检查内核配置"
fi

# 4) 磁盘：/ 至少 500MB 可用
AVAIL_MB=$(df -m / | awk 'NR==2{print $4}')
[ "$AVAIL_MB" -ge 500 ] || err "磁盘不足：/ 可用 ${AVAIL_MB}MB，需 >= 500MB"

# 5) 预编译包判定：有匹配二进制则免工具链，改查运行库（ldd 缺项即报）；
#    否则进入源码编译路径并检测工具链
PREBUILT=""
[ -f "$SCRIPT_DIR/bin/diting" ] && PREBUILT="$SCRIPT_DIR/bin/diting"
if [ -z "$PREBUILT" ] && [ ! -f "$SCRIPT_DIR/Makefile" ]; then
    err "既无预编译二进制 bin/diting，也无源码树 Makefile，安装包不完整"
fi

if [ -n "$PREBUILT" ]; then
    MISSING_LIBS=$(ldd "$PREBUILT" 2>/dev/null | awk '/not found/{print $1}' | sort -u)
    if [ -n "$MISSING_LIBS" ]; then
        err "预编译二进制缺运行库: $(echo $MISSING_LIBS | tr '\n' ' ')
      Ubuntu 一键补齐: apt install libfmt9 libyaml-cpp0.8 libsqlite3-0 libcurl4 libssl3 libelf1 zlib1g
      （22.04 对应 libfmt8 / libyaml-cpp0.7）"
    fi
fi

if [ -z "$PREBUILT" ]; then
    for tool in g++ clang bpftool make; do
        pkg="$tool"
        [ "$tool" = bpftool ] && pkg="linux-tools-generic"   # Ubuntu 无独立 bpftool 包
        command -v "$tool" >/dev/null 2>&1 || err "缺编译工具: $tool（apt install $pkg）"
    done
    # 容器/LXC 内 linux-tools 的 /usr/sbin/bpftool 是按 uname -r 分发的 shim，宿主内核
    # 无匹配 linux-tools-<ver> 包时 shim 失效；直接链接已安装的真实二进制兜底
    if command -v bpftool >/dev/null 2>&1 && ! bpftool version >/dev/null 2>&1; then
        REAL_BPFTOOL=$(ls /usr/lib/linux-tools-*/bpftool 2>/dev/null | head -1)
        if [ -n "$REAL_BPFTOOL" ]; then
            $SUDO ln -sf "$REAL_BPFTOOL" /usr/local/bin/bpftool
            echo "NOTE: bpftool shim 失效（容器环境），已链接真实二进制 $REAL_BPFTOOL → /usr/local/bin/bpftool"
        else
            err "bpftool shim 失效且未找到真实二进制（apt install linux-tools-generic）"
        fi
    fi
    # 头文件依赖 → apt 包名
    [ -f /usr/include/libelf.h ] || err "缺开发包: libelf-dev"
    [ -f /usr/include/zlib.h ] || err "缺开发包: zlib1g-dev"
    [ -e /usr/include/openssl/ssl.h ] || err "缺开发包: libssl-dev"
    [ -d /usr/include/fmt ] || err "缺开发包: libfmt-dev"
    [ -d /usr/include/yaml-cpp ] || err "缺开发包: libyaml-cpp-dev"
    [ -f /usr/include/sqlite3.h ] || err "缺开发包: libsqlite3-dev"
    [ -d /usr/include/curl ] || [ -d /usr/include/x86_64-linux-gnu/curl ] || err "缺开发包: libcurl4-openssl-dev"
fi

[ "$fail" -eq 0 ] || { echo "前置检测未通过，按以上缺项补齐后重跑"; exit 1; }
echo "前置检测通过（内核 $(uname -r)，磁盘可用 ${AVAIL_MB}MB）"

# ---------- 安装 ----------
# 0) 已在运行的服务先停，避免替换二进制时 text busy
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet diting 2>/dev/null; then
    echo "停止运行中的 diting 服务..."
    $SUDO systemctl stop diting
fi

# 1) 二进制
echo "[1/4] Installing binary..."
if [ -n "$PREBUILT" ]; then
    echo "  使用预编译二进制（跳过编译）"
else
    echo "[1/4] Compiling eBPF program..."
    make clean >/dev/null 2>&1 || true
    make -j"$(nproc)"
    PREBUILT="$SCRIPT_DIR/diting"
fi
$SUDO install -m 755 "$PREBUILT" /usr/local/bin/diting

# 2) 目录
echo "[2/4] Setting up config..."
$SUDO install -d -m 755 /etc/diting /var/log/diting /var/lib/diting

# 3) 配置口径分离：monitor 运行配置 与 check 工具配置 是两份不同文件
#    monitor.yaml 不存在才安装（保留现场改动）；check.yaml 同理
[ -f /etc/diting/monitor.yaml ] || $SUDO install -m 640 deploy/monitor.yaml /etc/diting/monitor.yaml
CHECK_CFG_SRC="baselines/default.yaml"
[ -f "$CHECK_CFG_SRC" ] || CHECK_CFG_SRC="config/check.yaml"   # 预编译包布局
[ -f /etc/diting/check.yaml ] || $SUDO install -m 640 "$CHECK_CFG_SRC" /etc/diting/check.yaml
# 旧版误装痕迹提示（check 配置曾被当 monitor 配置装到 rules.yaml）
if [ -f /etc/diting/rules.yaml ]; then
    echo "WARN: /etc/diting/rules.yaml 是旧版误装的 check 配置，monitor 已改用 monitor.yaml，核对后可删除"
fi

# 4) 核心规则包随包安装（包管目录，每次安装整体刷新；示例规则一并附带供参考）
echo "[3/4] Installing rules..."
$SUDO rm -rf /etc/diting/rules
$SUDO install -d -m 755 /etc/diting/rules
$SUDO cp -r rules/core rules/examples /etc/diting/rules/
RULES_INSTALLED=$(grep -rc '^- rule' /etc/diting/rules/core/*.yaml | awk -F: '{s+=$2} END {print s}')
echo "  核心规则 $RULES_INSTALLED 条 → /etc/diting/rules/core（示例规则 → rules/examples）"

# 4b) CIS 定义文件随包安装（diting cis check 默认路径；包管文件，每次安装刷新）
CIS_DEFS_SRC="cis/cis-baseline-v1.yaml"   # 源码树与预编译包布局一致
if [ -f "$CIS_DEFS_SRC" ]; then
    $SUDO install -m 644 "$CIS_DEFS_SRC" /etc/diting/cis-baseline-v1.yaml
    echo "  CIS 定义 → /etc/diting/cis-baseline-v1.yaml"
else
    echo "WARN: 未找到 $CIS_DEFS_SRC，diting cis check 需用 --defs 指定定义文件"
fi

# 5) systemd 服务（unit 文件照常落盘；无 systemd 的容器环境只跳过 daemon-reload）
echo "[4/4] Creating systemd service..."
$SUDO install -d -m 755 /etc/systemd/system
$SUDO install -m 644 deploy/diting.service /etc/systemd/system/diting.service
if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl daemon-reload
else
    echo "NOTE: 无 systemctl（容器环境），unit 已落盘但未 reload；手动起: diting monitor -c /etc/diting/monitor.yaml"
fi

echo ""
echo "=== Installation Complete ==="
echo "Start monitoring: sudo systemctl start diting"
echo "Enable on boot:   sudo systemctl enable diting"
echo "Check status:     sudo systemctl status diting"
echo "Run audit:        sudo diting check -c /etc/diting/check.yaml"
echo ""
echo "Monitor config:   /etc/diting/monitor.yaml"
echo "Check config:     /etc/diting/check.yaml"
echo "Rules dir:        /etc/diting/rules/core"
