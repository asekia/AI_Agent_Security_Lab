# MITRE ATLAS 技术矩阵与真实案例

> MITRE ATLAS Techniques & Cases · 分类：基础与威胁建模

## 1. 问题与定位

MITRE ATLAS 用 `AML.Txxxx` 编号回答"攻击者具体做了什么"，用 `AML.CSxxxx` 记录真实案例。与 OWASP 的分工：OWASP 回答"属于哪类风险"，ATLAS 回答"对手走到了哪一步"。

**用法**：把一次攻击链逐步映射到 ATLAS 技术，找出缺失的检测点；用案例编号作为威胁情报锚点。

## 2. 技术矩阵（本知识库涉及）

### 侦察与准备

| 编号 | 名称 | 含义 |
| --- | --- | --- |
| AML.T0000 | Search Open Technical Databases | 公开资料搜索（论文、博客、招聘） |
| AML.T0002 | Acquire Public AI Artifacts | 获取公开模型/数据集 |
| AML.T0005 | Create Proxy AI Model | 训练替代模型用于提取 |

### 初始访问与执行

| 编号 | 名称 | 含义 |
| --- | --- | --- |
| AML.T0010 | AI Supply Chain Compromise | 供应链入侵 |
| AML.T0049 | Exploit Public-Facing Application | 利用公开服务 |
| AML.T0051 | LLM Prompt Injection（.000 Direct / .001 Indirect / .002 Triggered） | 提示注入三型 |

### 数据与模型操纵

| 编号 | 名称 | 含义 |
| --- | --- | --- |
| AML.T0018 | Manipulate AI Model（.000 Poison / .001 Architecture / .002 Embed Malware） | 模型操纵 |
| AML.T0019 | Publish Poisoned Datasets | 发布投毒数据集 |
| AML.T0020 | Poison Training Data | 训练数据投毒 |
| AML.T0043 | Craft Adversarial Data | 构造对抗样本 |
| AML.T0015 | Evade AI Model | 规避模型检测 |
| AML.T0058 | Publish Poisoned Models | 发布投毒模型 |
| AML.T0109 | AI Supply Chain Rug Pull | 先正常后变坏 |

### 数据窃取与外带

| 编号 | 名称 | 含义 |
| --- | --- | --- |
| AML.T0057 | Data from Local System | 本地数据窃取 |
| AML.T0085 | Data from AI Services（.000 RAG Databases） | 从 AI 服务取数 |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | 借工具外带 |

### 案例

| 编号 | 案例 | 说明 |
| --- | --- | --- |
| AML.CS0023 | ShadowRay | Ray 仪表盘暴露 → 挖矿僵尸网络 |
| AML.CS0024 | Morris II Worm | 通过 RAG 邮件系统自我复制 |

## 3. 实战：用 ATLAS 做链条映射

### 步骤 1：列出攻击动作

```text
例：公开 issue 埋载荷 → Agent 读取 → 调用邮件工具 → 外发
```

### 步骤 2：逐动作映射

```text
T0000/T0002 → 侦察与获取公开资源
T0051.001   → 间接注入
T0086       → 工具调用外带
T0057       → 本地数据被读取
```

### 步骤 3：找检测缺口

对每个映射到的技术，问"日志里有没有对应信号"：

| 技术 | 检测信号 |
| --- | --- |
| T0051.001 | 检索片段含指令性语句 |
| T0086 | 无业务理由的工具调用 |
| T0057 | 工作区外读取 |
| T0010 | 新引入的依赖/模型来源 |

### 步骤 4：用案例校准

用 `AML.CSxxxx` 对照真实事件，检查自己的防护是否覆盖同类路径。

## 4. 与本项目的对应

| 本地位置 | 说明 |
| --- | --- |
| `docs/kb/inj-*.md` | T0051 家族的技术展开 |
| `docs/kb/inf-*.md` | T0049 / T0085 的基础设施侧 |
| `docs/kb/atk-chain.md` | 多技术串联的完整链条 |

## 5. 参考

- MITRE ATLAS：https://atlas.mitre.org/
- OWASP Agentic AI Top 10：https://genai.owasp.org/
