#include "rule_loader.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <filesystem>
#include <set>

#include "condition_parser.hpp"
#include "rule_engine.hpp"
#include "severity.hpp"

namespace detect {

namespace {

std::string err_at(const std::string &file, const YAML::Mark &mark, const std::string &reason) {
    return file + ":" + std::to_string(mark.line + 1) + ": " + reason;
}

bool load_file(const std::string &path, std::set<std::string> &names, std::vector<Rule> &out,
               std::string &err) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception &e) {
        err = path + ":" + std::to_string(e.mark.line + 1) + ": " + e.what();
        return false;
    }
    if (!root.IsSequence()) {
        err = err_at(path, root.Mark(), "规则文件顶层必须是规则列表");
        return false;
    }

    static const char *kRequired[] = {"rule", "desc", "condition", "output",
                                      "attack", "fpr_note", "response"};

    for (const auto &item : root) {
        if (!item.IsMap()) {
            err = err_at(path, item.Mark(), "规则条目必须是 map");
            return false;
        }
        for (const char *key : kRequired) {
            if (!item[key]) {
                err = err_at(path, item.Mark(), std::string("缺少必填字段: ") + key);
                return false;
            }
        }

        Rule rule;
        rule.source_file = path;
        try {
            rule.name = item["rule"].as<std::string>();
            rule.desc = item["desc"].as<std::string>();
            rule.output_template = item["output"].as<std::string>();
            // priority 可选（W5 D3）：缺省补 medium，不报错
            rule.priority = item["priority"] ? item["priority"].as<std::string>()
                                             : alert::SeverityDefault();
            rule.fpr_note = item["fpr_note"].as<std::string>();
            rule.response = item["response"].as<std::string>();
        } catch (const YAML::Exception &e) {
            err = err_at(path, e.mark, std::string("字段类型错误: ") + e.what());
            return false;
        }

        if (rule.name.empty()) {
            err = err_at(path, item["rule"].Mark(), "规则名不能为空");
            return false;
        }
        if (!names.insert(rule.name).second) {
            err = err_at(path, item["rule"].Mark(), "规则名全局重复: " + rule.name);
            return false;
        }
        if (!alert::SeverityIsValid(rule.priority)) {
            err =
                err_at(path, item["priority"].Mark(),
                       "非法 priority 值: " + rule.priority + "（枚举 critical/high/medium/low）");
            return false;
        }

        const YAML::Node &attack = item["attack"];
        if (!attack.IsSequence()) {
            err = err_at(path, attack.Mark(), "attack 必须是 ATT&CK 技术 ID 列表");
            return false;
        }
        for (const auto &t : attack) {
            try {
                rule.attack.push_back(t.as<std::string>());
            } catch (const YAML::Exception &e) {
                err = err_at(path, e.mark, "attack 列表元素必须是字符串");
                return false;
            }
        }

        const YAML::Node &cond_node = item["condition"];
        std::string cond_text;
        try {
            cond_text = cond_node.as<std::string>();
        } catch (const YAML::Exception &) {
            err = err_at(path, cond_node.Mark(), "condition 必须是字符串");
            return false;
        }
        std::string perr;
        rule.condition = ParseCondition(cond_text, perr);
        if (!rule.condition) {
            err = err_at(path, cond_node.Mark(), perr);
            return false;
        }

        // output 模板加载期校验（字段对照 schema 字段表；编译产物在引擎 Build 时重建）
        std::vector<TemplateSeg> segs;
        if (!ParseOutputTemplate(rule.output_template, segs, perr)) {
            err = err_at(path, item["output"].Mark(), perr);
            return false;
        }

        out.push_back(std::move(rule));
    }
    return true;
}

} // namespace

bool LoadRulesDir(const std::string &dir, std::vector<Rule> &out, std::string &err) {
    out.clear();
    err.clear();

    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        err = dir + ": 规则目录不存在或不是目录";
        return false;
    }

    std::vector<std::string> files;
    // 递归遍历（rules/examples/ 等子目录一并加载）
    for (const auto &entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
        if (!entry.is_regular_file())
            continue;
        const std::string ext = entry.path().extension().string();
        if (ext == ".yaml" || ext == ".yml")
            files.push_back(entry.path().string());
    }
    if (ec) {
        err = dir + ": 读取规则目录失败: " + ec.message();
        return false;
    }
    std::sort(files.begin(), files.end());

    std::set<std::string> names;
    for (const auto &f : files) {
        if (!load_file(f, names, out, err))
            return false;
    }
    return true;
}

namespace {

void extract_refs_from_node(const CondNode *node, const std::string &rule_name,
                            std::vector<FilePathRef> &out) {
    if (node == nullptr)
        return;
    switch (node->kind) {
    case CondNode::Kind::And:
    case CondNode::Kind::Or:
        for (const auto &c : node->children)
            extract_refs_from_node(c.get(), rule_name, out);
        return;
    case CondNode::Kind::Not:
        extract_refs_from_node(node->child.get(), rule_name, out);
        return;
    case CondNode::Kind::Compare: {
        const Operand *lit = nullptr;
        if (node->lhs.kind == Operand::Kind::Field && node->lhs.field == FieldId::file_path)
            lit = &node->rhs;
        else if (node->rhs.kind == Operand::Kind::Field && node->rhs.field == FieldId::file_path)
            lit = &node->lhs;
        else
            return;
        if (node->op == CmpOp::Eq && lit->kind == Operand::Kind::Str) {
            out.push_back({rule_name, lit->str});
        } else if (node->op == CmpOp::In && lit->kind == Operand::Kind::List) {
            for (const auto &elem : lit->list)
                if (elem.kind == Operand::Kind::Str)
                    out.push_back({rule_name, elem.str});
        }
        return;
    }
    }
}

} // namespace

std::vector<FilePathRef> ExtractFilePathRefs(const std::vector<Rule> &rules) {
    std::vector<FilePathRef> out;
    for (const auto &rule : rules)
        extract_refs_from_node(rule.condition.get(), rule.name, out);
    return out;
}

PathRefClass ClassifyPathRef(const std::string &path) {
    if (path.find_first_of("*?[]") != std::string::npos)
        return PathRefClass::Glob;
    if (path.empty() || path.front() != '/')
        return PathRefClass::NotAbsolute;
    return PathRefClass::Ok;
}

} // namespace detect
