#pragma once
#include <string>
#include "notifier.hpp"

// severity → syslog level 映射（纯函数，无 IO、无全局状态，供单测直接覆盖）。
// RFC 5424 severity 数值越小越严重；facility 固定 local0(16)，PRI = facility*8 + level。
namespace syslog_map {

inline int SeverityToLevel(const std::string& severity) {
    if (severity == "critical") return 2;  // LOG_CRIT
    if (severity == "high")     return 3;  // LOG_ERR
    if (severity == "medium")   return 4;  // LOG_WARNING
    if (severity == "low")      return 6;  // LOG_INFO
    return 6;  // 未知值按 info（与 notify_router 未知按 medium 的口径独立：外发不放大级别）
}

constexpr int kFacilityLocal0 = 16;

inline int Pri(const std::string& severity) {
    return kFacilityLocal0 * 8 + SeverityToLevel(severity);
}

}  // namespace syslog_map

// Syslog 渠道（INotifier 第二个实现，与 webhook 双通道并存）：
// RFC 5424 格式外发，APP-NAME=baseline-guard，SD 携带 rule_id/severity 等关键字段。
// 传输二选一（构造时定型）：host 非空 → UDP host:port（port 默认 514）；
// host 为空 → 本地 /dev/log（SOCK_DGRAM）。所配置的通道发送失败即 Send 返回 false。
//
// UDP 死端点检测：UDP 无连接，对死端口 sendto 也返回成功。此处用 connect() 过的
// UDP socket，发送后 poll(POLLERR) 等 ≤50ms 捕捉 ICMP port unreachable；错误一经
// 捕捉，本次 Send 返回 false（随后重试的 send 会直接 ECONNREFUSED），dispatcher
// 才能可靠计 failed。单次 Send 总耗时上限约 50ms（死端点）/ 微秒级（正常）。
class SyslogNotifier : public INotifier {
public:
    // host 空 = 本地 /dev/log；port 仅 UDP 路径有效
    SyslogNotifier(std::string host, int port);
    ~SyslogNotifier() override;

    bool Send(const AlertEvent& alert) override;
    std::string Name() const override { return "syslog"; }

private:
    std::string FormatMessage(const AlertEvent& alert) const;  // RFC 5424 全文
    bool EnsureSocket();   // 惰性建链；失败/错误后关闭，下次调用重建
    void CloseSocket();

    std::string host_;       // 空 = 本地 /dev/log
    int port_;
    int fd_ = -1;            // 已 connect 的 SOCK_DGRAM socket（仅工作线程访问）
    std::string hostname_;   // RFC 5424 HOSTNAME 字段（构造时取一次）
    int pid_ = 0;            // RFC 5424 PROCID 字段（构造时取一次）
};
