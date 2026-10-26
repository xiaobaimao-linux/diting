# W8 S2 误报专项（FPR）记录——AI 专项规则包（rules/core/ai-security.yaml 6 条）

> 方法（对齐 W6 D2/W7 D3）：单 monitor（tests/attack-cases/config.yaml，134 条 DSL 规则 + FIM 规则）下
> 依次执行 AI 场景日常操作，打标后统计新增 alerts。环境：vscode-server 远程开发机（无 GPU、无真实 CUDA 库）。
> 操作集：python3 读受管目录模型文件、python3 读受管目录外模型文件、python3 读受管目录非模型文件、
> python3 读 CUDA 库替身、`pip download --no-index --no-deps`（离线替身）、AI 运行时回环连接。
> **结论：6 条新规则误报 0 命中、收紧 0 处；白名单边界按 comm 集合，逐规则 fpr_note 已写明。**

## 反向验证明细（未命中即正确）

| 操作 | 涉及规则 | 结果 |
|---|---|---|
| python3 读受管目录模型文件（模拟 transformers/huggingface_hub 正常缓存访问） | ai_model_dir_access | 零命中（comm startswith python 豁免） |
| python3 读受管目录外模型文件（模拟本地推理脚本直接加载权重） | ai_model_file_read | 零命中（同上） |
| python3 读受管目录非模型文件（config.json） | ai_model_dir_access | 零命中（同上） |
| python3 读 CUDA 库替身（模拟训练进程加载 libcuda） | ai_cuda_inject | 零命中（同上） |
| `pip download --no-index --no-deps requests`（离线环境替身；comm 落 python3） | ai_model_file_* / ai_model_dir_access | 零命中；无外连故 ai_workload_outbound 亦不命中 |
| python3 连接 127.0.0.1 本地监听（模拟本地 vLLM/TGI 服务间调用、jupyter 调试） | ai_workload_outbound | 零命中（回环 dip 已豁免，case-34 负面对照同步断言 dip=127.0.0.1 告警 =0） |

## 正向边界验证（命中即正确）

- 非白名单（cat）读受管目录内**非模型**文件 config.json → ai_model_dir_access ×1（medium，无升级——
  该文件不是 model_file 资产），证明"目录内任何打开"语义不被模型扩展名限制。
- 无 GPU 机器上真实 libcuda//dev/nvidia* 字面量加载期逐条 warn 降级（G18 预期行为），
  命中链路由替身路径验证（case-35/36）。

## 已知噪声边界（不收紧，fpr_note 已声明）

1. **pip download（在线）/ huggingface 拉模型**：comm=python3 + 非回环 dip，必命中 ai_workload_outbound——
   这是规则本职（AI 运行时外连可见性）。允许列表（pypi.org/files.pythonhosted.org/huggingface.co/
   cdn-lfs*.hf.co/常见镜像站）因 DSL 在 connect 事件上只有 IP、无 CIDR（G20）、域名在 dns 事件无法
   跨事件关联（G5），只能确认后按 `and not network.dip in (ip, ...)` 逐字面量收敛，fpr_note 已写明可调。
2. **comm 白名单较宽是刻意取舍**：pip/conda/huggingface_hub 等 shebang 工具的 comm 都落在解释器名
   （python3），无法按工具区分（exe 同为解释器真实路径，G21）。白名单是降噪而非信任边界——
   comm 可被 argv[0] 伪造，攻击者改名 python* 即绕过；防绕过靠 exe/祖先链旁证与 W6 D4 升级联动，
   逐规则 fpr_note 已声明（G23：DSL 无 ai_workload 字段，无法按资产标记精确豁免）。
3. **备份/同步工具**（rsync/restic）全量扫模型目录会命中 ai_model_dir_access——按 comm 追加豁免。
4. **既有噪声不重复处理**：烟测期间 dsl.reverse_shell_from_web_service（examples 规则，
   lsb_release→dash 祖先链）命中 1 次，属 W6 F4 已知项，与本包无关。
