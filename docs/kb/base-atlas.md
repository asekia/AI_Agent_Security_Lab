# MITRE ATLAS 技术矩阵与真实案例

> MITRE ATLAS Techniques & Cases · 分类：基础与威胁建模

## 1. 一句话定义

MITRE ATLAS 是面向 AI 系统的攻击技术知识库，用 `AML.Txxxx` 编号回答"攻击者具体做了什么"。它和 OWASP 清单的分工是：OWASP 回答"属于哪类风险"，ATLAS 回答"对手走到了哪一步"。

## 2. 机制与原理

- 组织方式与 ATT&CK 一致：战术（Tactic）→ 技术（Technique）→ 子技术（`.000` / `.001`）。
- 案例用 `AML.CSxxxx` 编号，记录真实事件或公开研究，可作为威胁情报的锚点。
- 官方当前收录约 170 条技术（含子技术）与 57 个案例；本页只列与本知识库直接相关的部分，完整清单以官方为准。
- 覆盖阶段：侦察 → 资源准备 → 初始访问 → 执行 → 持久化 → 防御规避 → 发现 → 收集 → 外泄 → 影响。

## 3. 与本知识库相关的技术

### 侦察与资源准备

| 编号 | 技术 | 本知识库分类 |
| --- | --- | --- |
| AML.T0000 | Search Open Technical Databases | 基础与威胁建模 |
| AML.T0002 | Acquire Public AI Artifacts | AI 供应链 |
| AML.T0005 | Create Proxy AI Model | 模型与数据层 |
| AML.T0010 | AI Supply Chain Compromise | AI 供应链 |
| AML.T0019 | Publish Poisoned Datasets | 模型与数据层 |
| AML.T0058 | Publish Poisoned Models | AI 供应链 |
| AML.T0109 | AI Supply Chain Rug Pull | AI 供应链 |
| AML.T0018 | Manipulate AI Model（.000 Poison AI Model / .001 Modify AI Model Architecture / .002 Embed Malware） | 模型与数据层 |
| AML.T0020 | Poison Training Data | 模型与数据层 |
| AML.T0043 | Craft Adversarial Data | 模型与数据层 |
| AML.T0015 | Evade AI Model | 模型与数据层 |

### 初始访问与执行

| 编号 | 技术 | 本知识库分类 |
| --- | --- | --- |
| AML.T0049 | Exploit Public-Facing Application | AI 基础设施 |
| AML.T0051 | LLM Prompt Injection（.000 Direct / .001 Indirect / .002 Triggered） | 提示注入体系 |
| AML.T0065 | LLM Prompt Crafting | 提示注入体系 |
| AML.T0066 | Retrieval Content Crafting | 提示注入体系 |
| AML.T0068 | LLM Prompt Obfuscation | 编码混淆与扰动 |
| AML.T0093 | Prompt Infiltration via Public-Facing Application | 提示注入体系 |
| AML.T0094 | Delay Execution of LLM Instructions | 提示注入体系 |
| AML.T0054 | LLM Jailbreak | 越狱与说服工程 |

### 发现与收集

| 编号 | 技术 | 本知识库分类 |
| --- | --- | --- |
| AML.T0069 | Discover LLM System Information（.000 Special Character Sets / .001 System Instruction Keywords / .002 System Prompt） | 上下文与记忆 |
| AML.T0084 | Discover AI Agent Configuration（.000 Tool Definitions / .001 Agent Capabilities / .002 Agent Knowledge Base） | 智能体与信任 |
| AML.T0085 | Data from AI Services（.000 RAG Databases / .001 AI Agent Tools） | AI 基础设施 |
| AML.T0082 | RAG Credential Harvesting | 模型与数据层 |

### 持久化与投毒

| 编号 | 技术 | 本知识库分类 |
| --- | --- | --- |
| AML.T0070 | RAG Poisoning | 模型与数据层 |
| AML.T0071 | False RAG Entry Injection | 模型与数据层 |
| AML.T0080 | AI Agent Context Poisoning（.000 Memory / .001 Thread） | 上下文与记忆 |
| AML.T0092 | Manipulate User LLM Chat History | 上下文与记忆 |

### 外泄与影响

| 编号 | 技术 | 本知识库分类 |
| --- | --- | --- |
| AML.T0024 | Exfiltration via AI Inference API（.000 Infer Training Data Membership / .001 Invert AI Model / .002 Extract AI Model） | 模型与数据层 |
| AML.T0056 | Extract LLM System Prompt | 上下文与记忆 |
| AML.T0057 | LLM Data Leakage | 提示注入体系 |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | 智能体与信任 |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | 智能体与信任 |
| AML.T0060 | Publish Hallucinated Entities | 模型与数据层 |
| AML.T0067 | LLM Trusted Output Components Manipulation | 提示注入体系 |
| AML.T0029 | Denial of AI Service | 上下文与记忆 |
| AML.T0034 | Cost Harvesting | 上下文与记忆 |

## 4. 真实案例

**AML.CS0023 — ShadowRay。** 攻击者针对分布式 AI 框架对外暴露的控制面发起入侵，目标是真实世界里正在运行的 AI 训练基础设施。该案例的价值在于说明：AI 集群的控制面一旦可达，攻击者拿到的不只是算力，还包括其上运行的模型与数据。具体漏洞编号与时间线请以官方案例页为准。

**AML.CS0024 — Morris II 蠕虫。** 研究者在基于 RAG 的邮件系统中演示了一个可自我复制的恶意程序：投放邮件的内容被检索进模型上下文，模型在处理后续邮件时自动携带并传播这段载荷，全程不需要受害者点击。该案例说明"内容管道本身"可以成为传播路径——只处理文本的系统同样会被文本感染。

## 5. 检测与观察点

- 是否有针对 Agent 配置探测（T0084）的日志监控：短时间内大量询问工具清单、能力边界、知识库范围。
- 检索内容的写入是否有来源与时间记录，这是发现 RAG 投毒（T0070 / T0071）的前提。
- 模型制品与数据集的来源是否可验证、可追溯（T0019 / T0058 / T0109）。
- 工具调用是否记录发起者与完整参数（T0086 / T0101 的共同入口）。

## 6. 防御与改进

- 用 ATLAS 编号命名检测规则，便于与外部情报和内部事件对齐。
- 把"内容管道"当作完整链路来校验：抓取 → 清洗 → 切分 → 嵌入 → 检索 → 拼接，每一跳都记录来源。
- 对 Agent 工具调用做参数级审计，而不是只记录"调用了哪个工具"。
- 对模型制品做签名与哈希校验，阻断制品替换与 Rug Pull。

## 7. 与本项目的对应

| ATLAS 技术 | 本地场景 | 相关文件 |
| --- | --- | --- |
| AML.T0051.001 间接注入 | ASI01 目标劫持 | `seed/documents/*.md` |
| AML.T0070 / T0071 RAG 投毒 | ASI06 记忆投毒 | `lab/memory.py` |
| AML.T0054 越狱 | ASI01 / ASI09 演示 | `lab/runner.py` |
| AML.T0086 经由工具外泄 | ASI02 / ASI10 | `lab/tools.py` |
| AML.T0069 LLM 系统信息发现 | ASI01 原理篇 | `docs/asi01-principle.md` |

## 8. 参考

- MITRE ATLAS：https://atlas.mitre.org/
- MITRE ATLAS GitHub（技术与案例数据）：https://github.com/mitre-atlas/atlas-data
- OWASP Top 10 for LLM Applications (2025)：https://genai.owasp.org/llm-top-10/
- 内部培训笔记《llm 安全问题》
