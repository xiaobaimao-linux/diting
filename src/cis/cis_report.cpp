#include "cis_report.hpp"

#include "commonfun.hpp"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <sstream>

namespace cis {
namespace {

struct ResultCounts {
    int total = 0;
    int pass = 0;
    int fail = 0;
    int warn = 0;
};

void Tally(ResultCounts& counts, const std::string& result) {
    ++counts.total;
    if (result == "pass") ++counts.pass;
    if (result == "fail") ++counts.fail;
    if (result == "warn") ++counts.warn;
}

std::vector<CisResultRow> SortByCheckId(const std::vector<CisResultRow>& rows) {
    std::vector<CisResultRow> sorted = rows;
    std::sort(sorted.begin(), sorted.end(),
              [](const CisResultRow& a, const CisResultRow& b) {
                  return a.check_id < b.check_id;
              });
    return sorted;
}

std::string HtmlEscape(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (const char ch : input) {
        switch (ch) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out.push_back(ch); break;
        }
    }
    return out;
}

std::string SeverityLabel(const std::string& severity) {
    if (severity == "high") return "高";
    if (severity == "medium") return "中";
    if (severity == "low") return "低";
    return severity;
}

std::string ResultLabel(const std::string& result) {
    if (result == "pass") return "通过";
    if (result == "fail") return "不合规";
    if (result == "warn") return "警告";
    return result;
}

} // namespace

std::string RenderCisReportJson(const std::vector<CisResultRow>& rows, const std::string& host) {
    using nlohmann::json;
    const std::vector<CisResultRow> sorted = SortByCheckId(rows);

    ResultCounts total_counts;
    std::map<std::string, ResultCounts> by_severity{{"high", {}}, {"medium", {}}, {"low", {}}};
    for (const auto& row : sorted) {
        Tally(total_counts, row.result);
        auto it = by_severity.find(row.severity);
        if (it == by_severity.end()) {
            it = by_severity.emplace(row.severity, ResultCounts{}).first;
        }
        Tally(it->second, row.result);
    }

    json root;
    root["tool"] = "baseline-guard";
    root["report"] = "cis-baseline";
    root["schema_version"] = 1;
    root["generated_at"] = NowIso();
    root["host"] = host;

    json summary;
    summary["total"] = total_counts.total;
    summary["pass"] = total_counts.pass;
    summary["fail"] = total_counts.fail;
    summary["warn"] = total_counts.warn;
    const double pass_rate = total_counts.total > 0
                                 ? std::round(10000.0 * total_counts.pass / total_counts.total) / 10000.0
                                 : 0.0;
    summary["pass_rate"] = pass_rate;

    json sev_obj = json::object();
    for (const auto& [severity, counts] : by_severity) {
        json entry;
        entry["total"] = counts.total;
        entry["pass"] = counts.pass;
        entry["fail"] = counts.fail;
        entry["warn"] = counts.warn;
        sev_obj[severity] = entry;
    }
    summary["by_severity"] = sev_obj;
    root["summary"] = summary;

    json results = json::array();
    for (const auto& row : sorted) {
        json obj;
        obj["check_id"] = row.check_id;
        obj["category"] = row.category;
        obj["description"] = row.description;
        obj["severity"] = row.severity;
        obj["compliance"] = row.compliance;
        obj["result"] = row.result;
        obj["expected"] = row.expected;
        obj["remediation"] = row.expected;
        obj["actual"] = row.actual;
        obj["reason"] = row.reason;
        obj["checked_at"] = row.checked_at;
        obj["host"] = row.host;
        results.push_back(obj);
    }
    root["results"] = results;
    return root.dump(2);
}

std::string RenderCisReportHtml(const std::vector<CisResultRow>& rows, const std::string& host) {
    const std::vector<CisResultRow> sorted = SortByCheckId(rows);

    ResultCounts total_counts;
    std::map<std::string, ResultCounts> by_severity{{"high", {}}, {"medium", {}}, {"low", {}}};
    for (const auto& row : sorted) {
        Tally(total_counts, row.result);
        auto it = by_severity.find(row.severity);
        if (it == by_severity.end()) {
            it = by_severity.emplace(row.severity, ResultCounts{}).first;
        }
        Tally(it->second, row.result);
    }
    const double pass_rate = total_counts.total > 0
                                 ? 100.0 * total_counts.pass / total_counts.total
                                 : 0.0;

    std::ostringstream out;
    out << "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n"
        << "<meta charset=\"utf-8\">\n"
        << "<title>CIS 基线合规报告 - baseline-guard</title>\n"
        << "<style>\n"
        << "body{font-family:\"Helvetica Neue\",Arial,\"Microsoft YaHei\",sans-serif;margin:24px;color:#222;}\n"
        << "h1{font-size:22px;margin-bottom:4px;}\n"
        << ".meta{color:#666;font-size:13px;margin-bottom:16px;}\n"
        << ".summary{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:20px;}\n"
        << ".card{border:1px solid #ddd;border-radius:6px;padding:12px 18px;min-width:110px;}\n"
        << ".card .num{font-size:22px;font-weight:bold;}\n"
        << ".card .label{font-size:12px;color:#666;}\n"
        << "table{border-collapse:collapse;width:100%;font-size:13px;}\n"
        << "th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top;}\n"
        << "th{background:#f2f2f2;}\n"
        << "tr.fail{background:#fdd;}\n"
        << "tr.warn{background:#fff3cd;}\n"
        << "tr.pass{background:#e6f4ea;}\n"
        << "td.result.fail{color:#c00;font-weight:bold;}\n"
        << "td.result.warn{color:#8a6d00;font-weight:bold;}\n"
        << "td.result.pass{color:#1a7f37;}\n"
        << "</style>\n</head>\n<body>\n";

    out << "<h1>CIS 基线合规报告</h1>\n"
        << "<div class=\"meta\">工具: baseline-guard | 报告: cis-baseline | schema_version: 1 | 主机: "
        << HtmlEscape(host) << " | 生成时间: " << HtmlEscape(NowIso()) << "</div>\n";

    char rate_buf[32];
    std::snprintf(rate_buf, sizeof(rate_buf), "%.2f%%", pass_rate);
    out << "<div class=\"summary\">\n"
        << "<div class=\"card\"><div class=\"num\">" << total_counts.total << "</div><div class=\"label\">检查项总数</div></div>\n"
        << "<div class=\"card\"><div class=\"num\">" << rate_buf << "</div><div class=\"label\">通过率</div></div>\n"
        << "<div class=\"card\"><div class=\"num\">" << total_counts.pass << "</div><div class=\"label\">通过</div></div>\n"
        << "<div class=\"card\"><div class=\"num\">" << total_counts.fail << "</div><div class=\"label\">不合规</div></div>\n"
        << "<div class=\"card\"><div class=\"num\">" << total_counts.warn << "</div><div class=\"label\">警告</div></div>\n";
    for (const char* sev : {"high", "medium", "low"}) {
        const ResultCounts& counts = by_severity.at(sev);
        out << "<div class=\"card\"><div class=\"num\">" << counts.pass << "/" << counts.total
            << "</div><div class=\"label\">" << SeverityLabel(sev) << "级别通过 (fail " << counts.fail
            << " / warn " << counts.warn << ")</div></div>\n";
    }
    out << "</div>\n";

    out << "<table>\n<thead>\n<tr>"
        << "<th>ID</th><th>分类</th><th>描述</th><th>结果</th><th>级别</th>"
        << "<th>等保 2.0 条款号</th><th>修复建议</th><th>实际输出</th><th>判定理由</th><th>检查时间</th>"
        << "</tr>\n</thead>\n<tbody>\n";
    for (const auto& row : sorted) {
        const std::string cls = row.result == "fail" ? "fail"
                              : row.result == "warn" ? "warn" : "pass";
        out << "<tr class=\"" << cls << "\">"
            << "<td>" << HtmlEscape(row.check_id) << "</td>"
            << "<td>" << HtmlEscape(row.category) << "</td>"
            << "<td>" << HtmlEscape(row.description) << "</td>"
            << "<td class=\"result " << cls << "\">" << HtmlEscape(ResultLabel(row.result)) << "</td>"
            << "<td>" << HtmlEscape(SeverityLabel(row.severity)) << "</td>"
            << "<td>" << HtmlEscape(row.compliance) << "</td>"
            << "<td>" << HtmlEscape(row.expected) << "</td>"
            << "<td>" << HtmlEscape(row.actual) << "</td>"
            << "<td>" << HtmlEscape(row.reason) << "</td>"
            << "<td>" << HtmlEscape(row.checked_at) << "</td>"
            << "</tr>\n";
    }
    out << "</tbody>\n</table>\n</body>\n</html>\n";
    return out.str();
}

} // namespace cis
