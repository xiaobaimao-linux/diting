# 贡献指南

## 硬性条款：rules/ 改动必须回归

**任何改动 `rules/` 目录内容（新增/修改/删除/移动规则文件）或规则加载器代码
（`src/detect/rule_loader.*`、`src/detect/condition_parser.*`、`src/detect/rule_engine.*`、
monitor 规则加载路径）的提交，提交前必须跑攻击用例回归：**

```bash
sudo bash tests/attack-cases/run_all.sh
```

**最低门槛：30 用例 × 2 轮全过，检出率 100%（约定红线 ≥90%，低于红线禁止合入）。**

立规理由：W6 D3 往 `rules/` 放入 CIS 检查项定义文件（非 DSL 规则），递归加载解析失败
导致 DSL 引擎整体降级为空，期间只跑单测与冒烟、未跑用例回归，**告警空窗 2 天**
（D5 回归才发现，检出率 22.7%）。加载器类回归单测兜不住，只有端到端用例能兜住。

> W7 D1 已修复加载器 fail-fast（任一规则文件失败即拒绝启动），但"rules/ 改动必跑
> run_all.sh"作为提交纪律保留：规则内容本身的语义回归（误报/漏报/遮蔽）仍需用例网兜底。
