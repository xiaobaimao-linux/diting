# third_party 依赖清单

## libbpf v1.4.5

- 来源：https://github.com/libbpf/libbpf （tag `v1.4.5`，commit `a5086158dc90593b4e4b3ddbafab9bdaf9ec97ef`）
- 获取：`curl -sL https://github.com/libbpf/libbpf/archive/refs/tags/v1.4.5.tar.gz`
- 用途：静态链接进 `diting`，运行时零外部 libbpf 依赖
  （消灭 Ubuntu 22.04 stock libbpf 0.5 缺 `ring__*` API、`/usr/local` 自编译版本混用两类安装卡点）
- 删减：仅移除 `.github/` `.ci/` `ci/` `docs/` `fuzz/` `assets/`，`src/` 与 `include/` 完整保留，未打任何补丁
- 构建：顶层 Makefile 自动执行 `make -C third_party/libbpf/src BUILD_STATIC_ONLY=1`，
  头文件经 `install_headers` 布到 `third_party/libbpf/dest/usr/include/bpf/`
- 升级：替换目录并更新本文件的 tag/commit 即可
