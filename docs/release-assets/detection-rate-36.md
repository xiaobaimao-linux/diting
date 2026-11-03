# 36 攻击用例检出率表（v1.0.0-rc2 回归，2026-11-03）

数据来源：开发机 `tests/attack-cases/run_all.sh` 全量回归（36 用例 × 2 轮，exit=0，零 FAIL），结果原文 `/tmp/bg-attack-cases/results.txt`（72 行 PASS）。

| 类别（ATT&CK） | 用例 | 数量 | 检出（r1+r2） | 检出率 |
|---|---|---|---|---|
| 执行 Execution（TA0002） | case-01, 07~10 | 5 | 5+5 | 100% |
| 持久化 Persistence（TA0003） | case-19~22 | 4 | 4+4 | 100% |
| 防御规避 Defense Evasion（TA0005） | case-02, 03, 27~30 | 6 | 6+6 | 100% |
| 提权 Privilege Escalation（TA0004） | case-04, 06, 15~18 | 6 | 6+6 | 100% |
| 凭据访问 Credential Access（TA0006） | case-05, 11~14 | 5 | 5+5 | 100% |
| 挖矿 Impact/挖矿（TA0040） | case-23~26 | 4 | 4+4 | 100% |
| AI 安全专项 | case-31~36（含 AI 告警升级联动） | 6 | 6+6 | 100% |
| **合计** | | **36** | **36+36（72/72）** | **100%** |

说明：case-31~36 同时验证 AI 告警升级联动（medium→high / high→critical）；case-04/06 验证容器归属（cgroup 内核侧捕获）。flake 政策：本轮 0 次重跑、0 flake。
