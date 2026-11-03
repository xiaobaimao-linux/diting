# W10 校准纪要（W10 收官，草稿待人审）

> 日期：2026-11-03。口径：W10 无独立周计划文档落盘；清单按本周会话执行记录（S1~S4）还原。
> 数据引自 `docs/rc1-validation.md`（commit 8a0f75a）、`~/soak-archive/` 终态对账、
> W10 S4 回归（commit e4fd49b）与 `docs/install-matrix-w10.md`。

## 1. 完成率统计

| # | 计划项 | 状态 | 证据 |
|---|---|---|---|
| 1 | G25：5.15 内核 sendto 族探针 verifier 拒载根治 | ✓ | 位掩码收敛 qname_len；B 机全载；gaps 已关闭 |
| 2 | G25 证据链落盘（B 机 /root/g25） | ✓ | 已镜像开发机 `~/soak-archive/g25/`（16 个 log） |
| 3 | 全新安装矩阵双机 72/72 | ✓ | `docs/install-matrix-w10.md`，零 flake |
| 4 | soak 133h 收官对账（零丢包、RSS/CPU 红线） | ✓ | `~/soak-archive/soak-{A,B}-final-stats.txt`；A 144.0/B 133.7MB |
| 5 | v1.0.0-rc1 出炉（tag + 双 tarball + A 机全链路 6 步） | ✓ | `docs/rc1-validation.md`（commit 8a0f75a） |
| 6 | G26 修复（cis 定义随包 + 默认路径装后绝对路径） | ✓ | commit e4fd49b；cis check 零参数 40 项全判定 |
| 7 | v1.0.0-rc2（版本号 + 双 tarball + tag） | ✓ | 本纪要随附 S4 报告 |
| 8 | GitHub pre-release（rc2，双资产 + B 机对账验版） | ✓ | 见 S4 报告 URL |
| 9 | 发布材料轻量版三样（RSS 曲线/零丢包对账/检出率+等保截图） | ✓ | `docs/release-assets/` |
| 10 | 仓库地址迁移批量更新 + soak 两文档补票 | ✓ | report_generator 2 处；commit d3dac62 |
| 11 | 周检：36×2 + CIS 40 + 冒烟 RSS/CPU | ✓ | 72/72、pass19/fail21/未知0、138.7MB |
| 12 | 云机收口清单 + 本纪要 | ✓ | 见 S4 报告 §云机收口；本文档 |

**完成率 12/12 = 100%**（以 S4 报告为最终凭证；本纪要先行锁定口径）。

## 2. 出口标准达成

1. **出口①：36 攻击用例 ×2 轮全检出（flake 政策）**——达成。W10 S4 回归 72/72 零 FAIL 零重跑；
   安装矩阵双机 72/72 同口径复证。
2. **出口②：133h 双机稳定性（零丢包、零重启、资源红线内）**——达成。五类丢失计数全零、
   NRestarts=0；RSS 峰值 A 144.0MB / B 133.7MB（红线 150）；CPU 稳态 A 0.88% / B 0.51%。

## 3. G25/G26 两案始末（各三行）

- **G25（5.15 verifier 拒载）**：rc 前 B 机实测 sendto/sendmsg/sendmmsg 三探针 EPERM 拒载，
  初判 libbpf 版本兼容，变量隔离实验证伪（1.4.5/1.8.0 行为一致）。根因=22.04 容器 clang-14
  codegen 把 clamp 落到副本寄存器，5.15 verifier 无法跨寄存器回代上界。修法：位掩码收敛
  `qname_len &= sizeof-1`，任意 clang 版本均无法搬走上界证明；B 机四组合实测全载，关闭。
- **G26（cis 定义未随包）**：rc1 全链路验证暴露——tarball 不含定义文件、install.sh 不安装、
  默认路径为相对路径，装后任意 cwd 下 cis check 解析失败（--defs 可绕行，pass19/fail21 判定正常）。
  rc2 修复：tarball 纳入定义文件、install.sh 装 `/etc/diting/cis-baseline-v1.yaml`、
  kDefaultDefs 改装后绝对路径（源码树相对路径兜底），零参数直跑 40 项全判定，关闭。

## 4. RC 口径

- rc1（8a0f75a）：tag 与产物**封存不动**，G26 作为已知边界如实写入 CHANGELOG。
- rc2（e4fd49b）：仅含 G26 修复 + 仓库地址迁移，直升 rc2 不在已推 tag 下变异产物；
  pre-release 建在 rc2 上，双 tarball 以容器内 `VERSION=v1.0.0-rc2` 构建（规避无 git 回退默认版本号的 rc1 教训）。

## 5. 遗留项（排 v1.0.0 正式版/W11）

1. **tarball 构建闸 clang≥18**：22.04 容器默认 clang-14（G25 根因层）；正式版构建链应卡 clang≥18
   或固化掩码编码规范审查，防同类 codegen 回潮。
2. **bus.depth.hi=1 观察项**：soak 终态 A=1 / B=3（瞬时水位，未触发 queue_full），继续观察不处置。
3. **B 机 PEAK_RSS 数字补全**：已补——133.7MB（`soak-B-final.log` 1724 采样峰值），
   本纪要登账，W11 引用此数。
4. G9/G20/5.15 chown 降级/cmdline 256B 等已知边界：见 CHANGELOG Known limitations，口径不变。
