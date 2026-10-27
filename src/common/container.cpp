#include "container.hpp"

#include <cstdio>
#include <cstring>
#include <unistd.h>

// 从 cgroup 叶子目录名解析容器短 ID：支持 docker-/cri-containerd-/crio- 前缀
// （systemd 驱动带 .scope 后缀）及裸 hex 名（docker cgroupfs 驱动叶子名即全量 ID）。
// 事件字段仅 64 字节，长名（如 docker-<64hex>.scope 共 77 字符）会被截断，
// 故 hex 段按 ≥12 位接收（校验风格同 container_id_of），截前 12 位返回；
// 带前缀时 hex 段后仅允许空或 .scope 结尾，不匹配返回空串。
std::string parse_container_id_from_cgroup_name(const std::string& name)
{
    static const char *marks[] = {"docker-", "cri-containerd-", "crio-", nullptr};

    const char *hex = nullptr;
    for (int i = 0; marks[i]; i++) {
        size_t m = strlen(marks[i]);
        if (name.compare(0, m, marks[i]) == 0) {
            hex = name.c_str() + m;
            break;
        }
    }

    size_t n = 0;
    if (hex) {
        while (n < 64 && ((hex[n] >= '0' && hex[n] <= '9') || (hex[n] >= 'a' && hex[n] <= 'f')))
            n++;
        if (n >= 12 && (hex[n] == '\0' || strcmp(hex + n, ".scope") == 0))
            return std::string(hex, 12);
        return "";
    }

    // 裸 hex 名：整名全为十六进制且 ≥12 位（全量 64 hex 可能被事件字段截断）
    if (name.size() < 12)
        return "";
    for (n = 0; n < name.size(); n++) {
        char c = name[n];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return "";
    }
    return name.substr(0, 12);
}

// 移植自 ~/spike/exec_spike.c 的 container_id_of()，逻辑保持一致：
// /proc/<pid>/cgroup 逐行匹配运行时前缀，提取 64hex 截 12 位展示短 ID。
// 短寿进程 /proc 已回收属于正常场景，静默返回空串，由调用方省略字段。
std::string container_id_of(int pid)
{
    char path[64];
    char line[512];

    if (pid <= 0)
        return "";

    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return "";

    std::string cid;
    while (fgets(line, sizeof(line), f)) {
        static const char *marks[] = {"docker-", "cri-containerd-", "crio-", "docker/", nullptr};
        for (int i = 0; marks[i]; i++) {
            char *p = strstr(line, marks[i]);
            if (!p)
                continue;
            p += strlen(marks[i]);
            size_t n = 0;
            while (n < 64 && ((p[n] >= '0' && p[n] <= '9') || (p[n] >= 'a' && p[n] <= 'f')))
                n++;
            if (n >= 12) {
                cid.assign(p, 12);
                fclose(f);
                return cid;
            }
        }
    }

    fclose(f);
    return "";
}

std::string exe_path_of(int pid)
{
    char path[64];
    char buf[4096];

    if (pid <= 0)
        return "";

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0)
        return "";
    buf[n] = '\0';
    return std::string(buf);
}
