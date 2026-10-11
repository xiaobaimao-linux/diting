// 单元测试：CIS 检查判定逻辑（cis_judge）
// 编译: make test_cis_judge（见 tests/Makefile）

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

#include "cis_judge.hpp"

using cis::ExecOutcome;
using cis::Result;
using cis::Verdict;

static ExecOutcome outcome(bool launched, bool timed_out, int exit_code,
                           const std::string& output) {
    ExecOutcome o;
    o.launched = launched;
    o.timed_out = timed_out;
    o.exit_code = exit_code;
    o.output = output;
    return o;
}

// ====== CISJ-001: output "PASS\n" exit 0 -> pass ======
void test_pass_token() {
    const Verdict v = cis::Judge(outcome(true, false, 0, "PASS\n"));
    assert(v.result == Result::kPass);
    assert(v.reason.empty());
    printf("[PASS] CISJ-001: PASS token -> pass\n");
}

// ====== CISJ-002: output "FAIL\n" exit 0 -> fail ======
void test_fail_token() {
    const Verdict v = cis::Judge(outcome(true, false, 0, "FAIL\n"));
    assert(v.result == Result::kFail);
    assert(v.reason.empty());
    printf("[PASS] CISJ-002: FAIL token -> fail\n");
}

// ====== CISJ-003: output "garbage" exit 0 -> warn ======
void test_garbage_warn() {
    const Verdict v = cis::Judge(outcome(true, false, 0, "garbage"));
    assert(v.result == Result::kWarn);
    assert(v.reason.find("输出不可判定") != std::string::npos);
    printf("[PASS] CISJ-003: 无 token -> warn\n");
}

// ====== CISJ-004: timed_out=true（即使 output 含 PASS）-> warn ======
void test_timeout_warn() {
    const Verdict v = cis::Judge(outcome(true, true, 0, "PASS\n"));
    assert(v.result == Result::kWarn);
    assert(v.reason.find("超时") != std::string::npos);
    printf("[PASS] CISJ-004: timed_out -> warn\n");
}

// ====== CISJ-005: launched=false -> warn，reason 取 output 错误说明 ======
void test_not_launched_warn() {
    const Verdict v = cis::Judge(outcome(false, false, -1, "fork 失败: 资源不足"));
    assert(v.result == Result::kWarn);
    assert(v.reason == "fork 失败: 资源不足");
    printf("[PASS] CISJ-005: launched=false -> warn\n");
}

// ====== CISJ-006: output "FAIL\nPASS\n" -> pass（最后一个词生效）======
void test_last_token_wins() {
    const Verdict v = cis::Judge(outcome(true, false, 0, "FAIL\nPASS\n"));
    assert(v.result == Result::kPass);
    const Verdict v2 = cis::Judge(outcome(true, false, 0, "PASS\nFAIL\n"));
    assert(v2.result == Result::kFail);
    printf("[PASS] CISJ-006: 最后一个 token 生效\n");
}

// ====== CISJ-007: "PasswordAuthentication yes"（无独立 PASS 词）-> warn ======
void test_password_prefix_not_token() {
    const Verdict v = cis::Judge(outcome(true, false, 0, "PasswordAuthentication yes\n"));
    assert(v.result == Result::kWarn);
    printf("[PASS] CISJ-007: PasswordAuthentication 不算 PASS 词\n");
}

// ====== CISJ-008: exit 127 且无 token -> warn（exit_code 不作判定依据）======
void test_exit127_no_token_warn() {
    const Verdict v = cis::Judge(outcome(true, false, 127, "bash: xx: command not found\n"));
    assert(v.result == Result::kWarn);
    assert(v.reason.find("输出不可判定") != std::string::npos);
    // 有 token 时 exit_code 不影响结论
    const Verdict v2 = cis::Judge(outcome(true, false, 1, "PASS\n"));
    assert(v2.result == Result::kPass);
    printf("[PASS] CISJ-008: exit 127 无 token -> warn\n");
}

// ====== CISJ-009: ResultToString 映射 ======
void test_result_to_string() {
    assert(std::strcmp(cis::ResultToString(Result::kPass), "pass") == 0);
    assert(std::strcmp(cis::ResultToString(Result::kFail), "fail") == 0);
    assert(std::strcmp(cis::ResultToString(Result::kWarn), "warn") == 0);
    printf("[PASS] CISJ-009: ResultToString 映射\n");
}

// ====== CISJ-010: 不可判定 reason 截断 ≤120 字符且空白压缩 ======
void test_reason_truncation() {
    std::string long_output(300, 'x');
    const Verdict v = cis::Judge(outcome(true, false, 0, long_output));
    assert(v.result == Result::kWarn);
    // "输出不可判定: " 前缀 = 6 汉字×3 字节 + ": " 2 字节 = 20 字节；再截断 120 字符 + "..."
    assert(v.reason.size() <= 20 + 120 + 3);
    const Verdict v2 = cis::Judge(outcome(true, false, 0, "a  \n\tb"));
    assert(v2.reason.find("a b") != std::string::npos);
    printf("[PASS] CISJ-010: reason 截断与空白压缩\n");
}

int main() {
    test_pass_token();
    test_fail_token();
    test_garbage_warn();
    test_timeout_warn();
    test_not_launched_warn();
    test_last_token_wins();
    test_password_prefix_not_token();
    test_exit127_no_token_warn();
    test_result_to_string();
    test_reason_truncation();
    printf("[PASS] ALL test_cis_judge done\n");
    return 0;
}
