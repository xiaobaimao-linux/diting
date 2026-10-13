#include "cis_main.hpp"

#include "cis_check.hpp"
#include "cis_exec.hpp"
#include "cis_judge.hpp"
#include "cis_report.hpp"
#include "cis_store.hpp"
#include "commonfun.hpp"
#include "nlohmann/json.hpp"
#include "utils.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

using cis::CisCheckDef;
using cis::CisResultRow;
using cis::CisStore;
using cis::ExecOutcome;
using cis::Verdict;
using json = nlohmann::json;

const std::string kDefaultDb = "/var/lib/diting/baseline.db";
const std::string kDefaultDefs = "cis/cis-baseline-v1.yaml";

struct CommonOptions {
    std::string db_path = kDefaultDb;
    std::string defs_path = kDefaultDefs;
    bool json_output = false;
};

std::string ToUpper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
    return value;
}

void PrintCisUsage() {
    std::cout << "Usage: diting cis <check|report> [options]\n"
              << "\n"
              << "Subcommands:\n"
              << "  check     run CIS baseline checks and persist results\n"
              << "  report    show latest result per check from SQLite\n"
              << "\n"
              << "Common options:\n"
              << "  --db PATH    SQLite database path (default: " << kDefaultDb << ")\n"
              << "  --json       output structured JSON (legacy array format;\n"
              << "               for report, --format json gives the v1 schema)\n"
              << "\n"
              << "check options:\n"
              << "  --defs PATH      check definition YAML (default: " << kDefaultDefs << ")\n"
              << "  --category LIST  categories to run, repeatable or comma-separated\n"
              << "                   (default: AUTH,SSH,MISC)\n"
              << "\n"
              << "report options:\n"
              << "  --level L      filter by severity: high|medium|low\n"
              << "  --result R     filter by result: pass|fail|warn\n"
              << "  --format F     output format: text|json|html (default: text;\n"
              << "                 takes precedence over --json; html/json schema\n"
              << "                 see docs/cis-report-format-v1.md)\n"
              << "  --out PATH     write report to file (default: stdout)\n"
              << "  -h, --help   display this message\n";
}

// 解析公共选项，把已消费的位置参数标记到 consumed 里
bool ParseCommonOptions(int argc, char* argv[], CommonOptions& options, bool& help,
                        std::string& error, std::vector<bool>& consumed) {
    consumed.assign(argc, false);
    for (int i = 0; i < argc; ++i) {
        if (consumed[i]) continue;
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            help = true;
            consumed[i] = true;
            return true;
        }
        if (arg == "--db") {
            consumed[i] = true;
            if (!TakeArgValue(i, argc, argv, arg, options.db_path)) {
                error = "missing value for --db";
                return false;
            }
            consumed[i] = true;
        } else if (arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
            consumed[i] = true;
        } else if (arg == "--json") {
            options.json_output = true;
            consumed[i] = true;
        }
    }
    return true;
}

std::string TruncateSingleLine(const std::string& input, size_t limit) {
    std::string line;
    line.reserve(input.size());
    bool pending_space = false;
    for (const char ch : input) {
        if (std::isspace(static_cast<unsigned char>(ch))) {
            pending_space = !line.empty();
            continue;
        }
        if (pending_space) {
            line.push_back(' ');
            pending_space = false;
        }
        line.push_back(ch);
    }
    if (line.size() > limit) {
        line.resize(limit);
        line += "...";
    }
    return line;
}

json RowToJson(const CisResultRow& row) {
    json obj;
    obj["check_id"] = row.check_id;
    obj["category"] = row.category;
    obj["description"] = row.description;
    obj["severity"] = row.severity;
    obj["compliance"] = row.compliance;
    obj["result"] = row.result;
    obj["expected"] = row.expected;
    obj["actual"] = row.actual;
    obj["reason"] = row.reason;
    obj["checked_at"] = row.checked_at;
    obj["host"] = row.host;
    return obj;
}

int RunCheck(int argc, char* argv[]) {
    CommonOptions common;
    bool help = false;
    std::string error;
    std::vector<bool> consumed;
    if (!ParseCommonOptions(argc, argv, common, help, error, consumed)) {
        std::cerr << "Error: " << error << "\n";
        PrintCisUsage();
        return 2;
    }

    std::set<std::string> categories;
    bool category_given = false;
    for (int i = 0; i < argc; ++i) {
        if (consumed[i]) continue;
        const std::string arg = argv[i];
        std::string value;
        if (arg == "--defs") {
            if (!TakeArgValue(i, argc, argv, arg, common.defs_path)) {
                std::cerr << "Error: missing value for --defs\n";
                PrintCisUsage();
                return 2;
            }
        } else if (arg.rfind("--defs=", 0) == 0) {
            common.defs_path = arg.substr(7);
        } else if (arg == "--category") {
            if (!TakeArgValue(i, argc, argv, arg, value)) {
                std::cerr << "Error: missing value for --category\n";
                PrintCisUsage();
                return 2;
            }
            category_given = true;
        } else if (arg.rfind("--category=", 0) == 0) {
            value = arg.substr(11);
            category_given = true;
        } else {
            std::cerr << "Error: unknown check option: " << arg << "\n";
            PrintCisUsage();
            return 2;
        }
        if (!value.empty()) {
            size_t start = 0;
            while (start <= value.size()) {
                const size_t comma = value.find(',', start);
                const std::string item = value.substr(
                    start, comma == std::string::npos ? std::string::npos : comma - start);
                if (!item.empty()) {
                    categories.insert(ToUpper(item));
                }
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
        }
    }
    if (help) {
        PrintCisUsage();
        return 0;
    }
    if (!category_given) {
        categories = {"AUTH", "SSH", "MISC"};
    }

    std::vector<CisCheckDef> defs;
    std::string load_err;
    if (!cis::LoadCisChecks(common.defs_path, defs, load_err)) {
        std::cerr << "Error: " << load_err << "\n";
        return 1;
    }

    std::vector<CisCheckDef> selected;
    for (const auto& def : defs) {
        if (categories.count(ToUpper(def.category)) > 0) {
            selected.push_back(def);
        }
    }

    CisStore store(common.db_path);
    const std::string host = GetHostname();
    const std::string checked_at = NowIso();

    if (!category_given && !common.json_output) {
        std::cout << "LOG/NET/FILE 为 D4 范围，本次未执行" << std::endl;
    }

    int pass_count = 0;
    int fail_count = 0;
    int warn_count = 0;
    json json_results = json::array();

    for (const auto& def : selected) {
        ExecOutcome outcome;
        std::string hit;
        if (!cis::CommandIsReadOnly(def.command, hit)) {
            outcome.launched = false;
            outcome.output = "命令含潜在写操作(" + hit + ")，拒绝执行";
        } else {
            outcome = cis::RunCheckCommand(def.command, 5);
        }
        const Verdict verdict = cis::Judge(outcome);
        const char* result_str = cis::ResultToString(verdict.result);
        switch (verdict.result) {
        case cis::Result::kPass:
            ++pass_count;
            break;
        case cis::Result::kFail:
            ++fail_count;
            break;
        case cis::Result::kWarn:
            ++warn_count;
            break;
        }

        CisResultRow row;
        row.check_id = def.id;
        row.category = def.category;
        row.description = def.description;
        row.severity = def.severity;
        row.compliance = def.compliance;
        row.result = result_str;
        row.expected = def.expected;
        row.actual = TruncateSingleLine(outcome.output, 200);
        row.reason = verdict.reason;
        row.checked_at = checked_at;
        row.host = host;
        store.SaveResult(row);

        if (common.json_output) {
            json_results.push_back(RowToJson(row));
        } else {
            std::cout << std::left << std::setw(10) << def.id << "[" << std::setw(6)
                      << result_str << "] " << def.description;
            if (verdict.result == cis::Result::kWarn) {
                std::cout << "  (" << verdict.reason << ")";
            }
            std::cout << std::endl;
        }
    }

    if (common.json_output) {
        json root;
        root["results"] = json_results;
        json summary;
        summary["pass"] = pass_count;
        summary["fail"] = fail_count;
        summary["warn"] = warn_count;
        summary["total"] = static_cast<int>(selected.size());
        root["summary"] = summary;
        std::cout << root.dump(2) << std::endl;
    } else {
        std::cout << "cis check summary: pass " << pass_count << " / fail " << fail_count
                  << " / warn " << warn_count << " (total " << selected.size() << ")"
                  << std::endl;
    }
    return 0;
}

// 写报告内容到 out_path（空则写 stdout）；失败返回 false
bool WriteReportOutput(const std::string& content, const std::string& out_path) {
    if (out_path.empty()) {
        std::cout << content << std::endl;
        return true;
    }
    std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        std::cerr << "Error: cannot open output file: " << out_path << "\n";
        return false;
    }
    ofs << content;
    return static_cast<bool>(ofs);
}

int RunReport(int argc, char* argv[]) {
    CommonOptions common;
    bool help = false;
    std::string error;
    std::vector<bool> consumed;
    if (!ParseCommonOptions(argc, argv, common, help, error, consumed)) {
        std::cerr << "Error: " << error << "\n";
        PrintCisUsage();
        return 2;
    }

    std::string level;
    std::string result_filter;
    std::string format;
    std::string out_path;
    for (int i = 0; i < argc; ++i) {
        if (consumed[i]) continue;
        const std::string arg = argv[i];
        if (arg == "--level") {
            if (!TakeArgValue(i, argc, argv, arg, level)) {
                std::cerr << "Error: missing value for --level\n";
                PrintCisUsage();
                return 2;
            }
        } else if (arg.rfind("--level=", 0) == 0) {
            level = arg.substr(8);
        } else if (arg == "--result") {
            if (!TakeArgValue(i, argc, argv, arg, result_filter)) {
                std::cerr << "Error: missing value for --result\n";
                PrintCisUsage();
                return 2;
            }
        } else if (arg.rfind("--result=", 0) == 0) {
            result_filter = arg.substr(9);
        } else if (arg == "--format") {
            if (!TakeArgValue(i, argc, argv, arg, format)) {
                std::cerr << "Error: missing value for --format\n";
                PrintCisUsage();
                return 2;
            }
        } else if (arg.rfind("--format=", 0) == 0) {
            format = arg.substr(9);
        } else if (arg == "--out") {
            if (!TakeArgValue(i, argc, argv, arg, out_path)) {
                std::cerr << "Error: missing value for --out\n";
                PrintCisUsage();
                return 2;
            }
        } else if (arg.rfind("--out=", 0) == 0) {
            out_path = arg.substr(6);
        } else {
            std::cerr << "Error: unknown report option: " << arg << "\n";
            PrintCisUsage();
            return 2;
        }
    }
    if (help) {
        PrintCisUsage();
        return 0;
    }
    if (!level.empty() && level != "high" && level != "medium" && level != "low") {
        std::cerr << "Error: invalid level: " << level << " (high|medium|low)\n";
        return 2;
    }
    if (!result_filter.empty() && result_filter != "pass" && result_filter != "fail" &&
        result_filter != "warn") {
        std::cerr << "Error: invalid result: " << result_filter << " (pass|fail|warn)\n";
        return 2;
    }
    if (!format.empty() && format != "text" && format != "json" && format != "html") {
        std::cerr << "Error: invalid format: " << format << " (text|json|html)\n";
        return 2;
    }

    CisStore store(common.db_path);
    const std::vector<CisResultRow> rows = store.GetLatest(level, result_filter);

    // --format 优先于旧 --json 开关
    if (format == "json") {
        return WriteReportOutput(cis::RenderCisReportJson(rows, GetHostname()), out_path) ? 0 : 1;
    }
    if (format == "html") {
        return WriteReportOutput(cis::RenderCisReportHtml(rows, GetHostname()), out_path) ? 0 : 1;
    }

    if (format.empty() && common.json_output) {
        json root = json::array();
        for (const auto& row : rows) {
            root.push_back(RowToJson(row));
        }
        std::cout << root.dump(2) << std::endl;
        return 0;
    }

    // text 格式（默认）：现有表格行为不变；指定 --out 时写入文件
    std::ostringstream text_buf;
    std::ostream& os = out_path.empty() ? std::cout : text_buf;

    if (rows.empty()) {
        os << "No cis results found." << std::endl;
        if (!out_path.empty()) {
            return WriteReportOutput(text_buf.str(), out_path) ? 0 : 1;
        }
        return 0;
    }

    os << std::left << std::setw(10) << "CHECK_ID" << std::setw(9) << "SEVERITY"
       << std::setw(8) << "RESULT" << std::setw(12) << "COMPLIANCE"
       << std::setw(42) << "DESCRIPTION" << std::setw(21) << "CHECKED_AT"
       << "HOST" << std::endl;
    os << std::string(120, '-') << std::endl;
    int pass_count = 0;
    int fail_count = 0;
    int warn_count = 0;
    for (const auto& row : rows) {
        std::string desc = row.description;
        if (desc.size() > 40) {
            size_t cut = 40;
            while (cut > 0 && (static_cast<unsigned char>(desc[cut]) & 0xC0) == 0x80) {
                --cut;
            }
            desc = desc.substr(0, cut) + "..";
        }
        os << std::left << std::setw(10) << row.check_id << std::setw(9)
           << row.severity << std::setw(8) << row.result << std::setw(12)
           << row.compliance << std::setw(42) << desc << std::setw(21)
           << row.checked_at << row.host << std::endl;
        if (row.result == "pass") ++pass_count;
        if (row.result == "fail") ++fail_count;
        if (row.result == "warn") ++warn_count;
    }
    os << "rows: " << rows.size() << " (pass " << pass_count << " / fail "
       << fail_count << " / warn " << warn_count << ")" << std::endl;
    if (!out_path.empty()) {
        return WriteReportOutput(text_buf.str(), out_path) ? 0 : 1;
    }
    return 0;
}

} // namespace

int RunCis(int argc, char* argv[]) {
    if (argc < 1) {
        PrintCisUsage();
        return 2;
    }
    const std::string subcmd = argv[0];
    try {
        if (subcmd == "check") {
            return RunCheck(argc - 1, argv + 1);
        }
        if (subcmd == "report") {
            return RunReport(argc - 1, argv + 1);
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
    std::cerr << "Error: unknown cis subcommand: " << subcmd << "\n";
    PrintCisUsage();
    return 2;
}
