// 单元测试：syslog 渠道 severity → syslog level 映射纯函数（syslog_notifier.hpp）
// 编译: g++ -std=c++17 -I../../src -I../../src/common -I../../src/alerts \
//       -o test_syslog_severity test_syslog_severity.cpp

#include <cassert>
#include <cstdio>
#include "syslog_notifier.hpp"

// ====== SYS-001: severity → syslog level 全映射 ======
void test_severity_to_level() {
    assert(syslog_map::SeverityToLevel("critical") == 2);  // LOG_CRIT
    assert(syslog_map::SeverityToLevel("high")     == 3);  // LOG_ERR
    assert(syslog_map::SeverityToLevel("medium")   == 4);  // LOG_WARNING
    assert(syslog_map::SeverityToLevel("low")      == 6);  // LOG_INFO
    printf("  [PASS] SYS-001: severity → syslog level 全映射\n");
}

// ====== SYS-002: 未知/空值回退 info ======
void test_unknown_fallback() {
    assert(syslog_map::SeverityToLevel("") == 6);
    assert(syslog_map::SeverityToLevel("weird") == 6);
    assert(syslog_map::SeverityToLevel("CRITICAL") == 6);  // 大小写敏感，未知按 info
    printf("  [PASS] SYS-002: 未知 severity 回退 info\n");
}

// ====== SYS-003: PRI = facility(16) * 8 + level ======
void test_pri() {
    assert(syslog_map::Pri("critical") == 16 * 8 + 2);   // 130
    assert(syslog_map::Pri("high")     == 16 * 8 + 3);   // 131
    assert(syslog_map::Pri("medium")   == 16 * 8 + 4);   // 132
    assert(syslog_map::Pri("low")      == 16 * 8 + 6);   // 134
    assert(syslog_map::Pri("bogus")    == 16 * 8 + 6);   // 未知按 info
    printf("  [PASS] SYS-003: PRI 计算（local0 facility）\n");
}

int main() {
    printf("=== test_syslog_severity ===\n");
    test_severity_to_level();
    test_unknown_fallback();
    test_pri();
    printf("=== all syslog_severity tests passed ===\n");
    return 0;
}
