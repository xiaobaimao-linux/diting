#include "syslog_notifier.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <netdb.h>
#include <poll.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

// RFC 5424 TIMESTAMP：2026-10-13T12:34:56.123456+08:00（本地时区，微秒精度）
std::string Rfc5424Timestamp() {
    struct timespec ts {};
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv {};
    localtime_r(&ts.tv_sec, &tmv);
    char main_part[24];
    strftime(main_part, sizeof(main_part), "%Y-%m-%dT%H:%M:%S", &tmv);
    char tz[8];
    strftime(tz, sizeof(tz), "%z", &tmv);   // +0800，RFC 5424 要求 +08:00
    const size_t tz_len = std::strlen(tz);
    char out[64];
    if (tz_len >= 3) {
        std::snprintf(out, sizeof(out), "%s.%06ld%.*s:%s", main_part, ts.tv_nsec / 1000,
                      static_cast<int>(tz_len - 2), tz, tz + tz_len - 2);
    } else {
        std::snprintf(out, sizeof(out), "%s.%06ldZ", main_part, ts.tv_nsec / 1000);
    }
    return out;
}

// RFC 5424 PARAM-VALUE 转义：\ " ] 三个字符必须反斜杠转义
std::string EscapeSdValue(const std::string& v) {
    std::string out;
    out.reserve(v.size() + 8);
    for (const char c : v) {
        if (c == '\\' || c == '"' || c == ']') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    return out;
}

}  // namespace

SyslogNotifier::SyslogNotifier(std::string host, int port)
    : host_(std::move(host)), port_(port) {
    char buf[256] = {};
    if (gethostname(buf, sizeof(buf) - 1) == 0) {
        hostname_ = buf;
    } else {
        hostname_ = "-";   // RFC 5424 NILVALUE
    }
    pid_ = static_cast<int>(getpid());
}

SyslogNotifier::~SyslogNotifier() {
    CloseSocket();
}

void SyslogNotifier::CloseSocket() {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

bool SyslogNotifier::EnsureSocket() {
    if (fd_ >= 0) {
        return true;
    }
    if (host_.empty()) {
        // 本地路径：/dev/log（SOCK_DGRAM）。connect 即探测 syslog 守护进程
        // 是否存在：无 /dev/log 时 ENOENT，存在但无人接收时后续 send 得
        // ECONNREFUSED，两类失败都会让 Send 返回 false
        fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd_ < 0) {
            spdlog::warn("[notify] syslog /dev/log socket() failed: {}", strerror(errno));
            return false;
        }
        struct sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, "/dev/log", sizeof(addr.sun_path) - 1);
        if (connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            spdlog::warn("[notify] syslog connect /dev/log failed: {}", strerror(errno));
            CloseSocket();
            return false;
        }
        return true;
    }

    // UDP 路径：connect() 过的 SOCK_DGRAM socket，使 ICMP port unreachable
    // 能以 POLLERR / ECONNREFUSED 形式回到本 socket（未 connect 则完全收不到）
    struct addrinfo hints {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res) != 0) {
        spdlog::warn("[notify] syslog resolve {}:{} failed", host_, port_);
        return false;
    }
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd_ = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd_ < 0) {
            continue;
        }
        if (connect(fd_, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        CloseSocket();
    }
    freeaddrinfo(res);
    if (fd_ < 0) {
        spdlog::warn("[notify] syslog connect {}:{} failed: {}", host_, port_,
                     strerror(errno));
        return false;
    }
    return true;
}

std::string SyslogNotifier::FormatMessage(const AlertEvent& alert) const {
    // <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
    std::string msg;
    msg.reserve(512);
    msg.push_back('<');
    msg += std::to_string(syslog_map::Pri(alert.severity));
    msg += ">1 ";
    msg += Rfc5424Timestamp();
    msg.push_back(' ');
    msg += hostname_;
    msg += " diting ";
    msg += std::to_string(pid_);
    msg.push_back(' ');
    msg += alert.rule_id.empty() ? "-" : alert.rule_id;   // MSGID 用 rule_id
    msg += " [diting rule_id=\"";
    msg += EscapeSdValue(alert.rule_id);
    msg += "\" severity=\"";
    msg += EscapeSdValue(alert.severity);
    msg += "\" event_type=\"";
    msg += EscapeSdValue(alert.event_type);
    msg += "\" action=\"";
    msg += EscapeSdValue(alert.action_taken);
    msg += "\" occurrences=\"";
    msg += std::to_string(alert.occurrences);
    msg += "\"]";
    // MSG：可读摘要（聚合摘要附首末时间，与 webhook payload 口径一致）
    msg += " rule=";
    msg += alert.rule_id;
    msg += " severity=";
    msg += alert.severity;
    if (!alert.file_path.empty()) {
        msg += " file=";
        msg += alert.file_path;
    }
    if (!alert.process_name.empty()) {
        msg += " proc=";
        msg += alert.process_name;
        msg += "(";
        msg += std::to_string(alert.pid);
        msg += ")";
    }
    if (!alert.user_name.empty()) {
        msg += " user=";
        msg += alert.user_name;
    }
    if (!alert.expected.empty() || !alert.actual.empty()) {
        msg += " expected=";
        msg += alert.expected;
        msg += " actual=";
        msg += alert.actual;
    }
    if (alert.occurrences > 1) {
        msg += " occurrences=";
        msg += std::to_string(alert.occurrences);
        msg += " first_seen=";
        msg += alert.first_seen;
        msg += " last_seen=";
        msg += alert.last_seen;
    }
    return msg;
}

bool SyslogNotifier::Send(const AlertEvent& alert) {
    const std::string msg = FormatMessage(alert);
    if (!EnsureSocket()) {
        return false;
    }

    const ssize_t n = send(fd_, msg.data(), msg.size(), MSG_NOSIGNAL);
    if (n < 0) {
        // connected UDP 的后续 send 遇历史 ICMP 错误直接 ECONNREFUSED；
        // /dev/log 无人接收时同样 ECONNREFUSED
        spdlog::warn("[notify] syslog send failed: {}", strerror(errno));
        CloseSocket();
        return false;
    }

    if (!host_.empty()) {
        // UDP 死端点检测：首包 send 必然"成功"（无连接），等 ≤50ms 让对端
        // ICMP port unreachable 回到本 socket（POLLERR）。本机/同网段 ICMP
        // 为 RTT 级（远小于 50ms）；超时按成功处理（中间设备静默丢包无法区分，
        // 与 webhook 的"发送即成功"口径一致的可观测性上限）
        struct pollfd pfd {fd_, POLLERR, 0};
        const int pr = poll(&pfd, 1, 50);
        if (pr > 0 && (pfd.revents & POLLERR) != 0) {
            int soerr = 0;
            socklen_t len = sizeof(soerr);
            getsockopt(fd_, SOL_SOCKET, SO_ERROR, &soerr, &len);   // 读出即清除
            spdlog::warn("[notify] syslog UDP endpoint error: {}", strerror(soerr));
            CloseSocket();
            return false;
        }
    }
    return true;
}
