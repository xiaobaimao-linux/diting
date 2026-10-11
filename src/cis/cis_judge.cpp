#include "cis_judge.hpp"

#include <cctype>

namespace cis {

namespace {

constexpr size_t kReasonOutputLimit = 120;

bool IsWordChar(char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0;
}

// 找 output 中最后一个独立词 token（"PASS" 或 "FAIL"），返回指针或 nullptr。
const char* LastVerdictToken(const std::string& output) {
    const char* last = nullptr;
    for (size_t i = 0; i + 4 <= output.size(); ++i) {
        const bool is_pass = output.compare(i, 4, "PASS") == 0;
        const bool is_fail = !is_pass && output.compare(i, 4, "FAIL") == 0;
        if (!is_pass && !is_fail) continue;
        const bool left_ok = (i == 0) || !IsWordChar(output[i - 1]);
        const bool right_ok = (i + 4 >= output.size()) || !IsWordChar(output[i + 4]);
        if (left_ok && right_ok) {
            last = is_pass ? "PASS" : "FAIL";
        }
    }
    return last;
}

std::string CompactOutput(const std::string& output) {
    std::string compact;
    compact.reserve(output.size());
    bool pending_space = false;
    for (const char ch : output) {
        if (std::isspace(static_cast<unsigned char>(ch))) {
            pending_space = !compact.empty();
            continue;
        }
        if (pending_space) {
            compact.push_back(' ');
            pending_space = false;
        }
        compact.push_back(ch);
    }
    if (compact.size() > kReasonOutputLimit) {
        compact.resize(kReasonOutputLimit);
        compact += "...";
    }
    return compact;
}

} // namespace

Verdict Judge(const ExecOutcome& o) {
    if (!o.launched) {
        return Verdict{Result::kWarn, o.output};
    }
    if (o.timed_out) {
        return Verdict{Result::kWarn, "执行超时(>5s)"};
    }
    const char* token = LastVerdictToken(o.output);
    if (token != nullptr) {
        return Verdict{token[0] == 'P' ? Result::kPass : Result::kFail, ""};
    }
    return Verdict{Result::kWarn, "输出不可判定: " + CompactOutput(o.output)};
}

const char* ResultToString(Result r) {
    switch (r) {
    case Result::kPass:
        return "pass";
    case Result::kFail:
        return "fail";
    case Result::kWarn:
        return "warn";
    }
    return "warn";
}

} // namespace cis
