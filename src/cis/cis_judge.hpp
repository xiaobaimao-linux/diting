#pragma once

#include <string>

namespace cis {

enum class Result { kPass, kFail, kWarn };

struct ExecOutcome {
    bool launched = false;
    bool timed_out = false;
    int exit_code = 0;
    std::string output;
};

struct Verdict {
    Result result = Result::kWarn;
    std::string reason;  // pass/fail 时为空
};

// 判定一次执行的结论：
//   !launched -> warn（reason 取 output 中的错误说明）
//   timed_out -> warn（reason "执行超时(>5s)"）
//   否则在 output 中找最后一个独立词 PASS/FAIL（词边界：前后非字母数字）；
//   都无 -> warn（reason "输出不可判定: " + 截断≤120 字符、空白压缩为单空格的输出）。
// exit_code 不作为判定依据（有 token 时以 token 为准）。
Verdict Judge(const ExecOutcome& o);

const char* ResultToString(Result r);

} // namespace cis
