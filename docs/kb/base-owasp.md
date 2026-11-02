# OWASP LLM Top 10 (2025) 与 Agentic AI Top 10 (2026)

> OWASP LLM & Agentic Top 10 · 分类：基础与威胁建模

## 1. 问题与定位

两套清单描述同一系统的两个尺度：**LLM Top 10 (2025)** 以模型及其宿主应用为中心；**Agentic AI Top 10 (2026)** 以具备工具调用、跨会话记忆与多体协作能力的 Agent 为中心。

**用法**：拿到一个事件或设计，先问"属于哪类风险"（OWASP 编号），再问"对手走到哪一步"（ATLAS 技术编号），最后问"我的哪条硬约束没拦住"。

## 2. LLM Top 10 (2025)

| 编号 | 官方名称 | 核心问题 | 对应攻击入口 |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | 输入或外部内容改变模型行为 | 用户输入、检索内容 |
| LLM02 | Sensitive Information Disclosure | 输出或系统环节暴露敏感数据 | 提示泄露、日志、错误回显 |
| LLM03 | Supply Chain | 第三方模型/数据集/插件引入弱点 | 依赖、模型仓库 |
| LLM04 | Data and Model Poisoning | 训练/微调/嵌入数据被污染 | 数据集、微调 |
| LLM05 | Improper Output Handling | 输出未校验进入危险上下文 | HTML/SQL/命令 |
| LLM06 | Excessive Agency | 权限、功能或自主性过大 | 工具、凭证 |
| LLM07 | System Prompt Leakage | 系统提示被套取 | 结构侦察、翻译包装 |
| LLM08 | Vector and Embedding Weaknesses | 向量库访问控制与污染 | 检索、嵌入 |
| LLM09 | Misinformation | 看似可信的错误内容 | 信任利用 |
| LLM10 | Unbounded Consumption | 资源与成本无界消耗 | 超长输入、循环 |

## 3. Agentic AI Top 10 (2026)

| 编号 | 官方名称 | 核心问题 |
| --- | --- | --- |
| ASI01 | Agent Goal Hijacking | 目标被外部内容改写 |
| ASI02 | Tool Misuse & Exploitation | 合法工具被非预期使用 |
| ASI03 | Identity & Privilege Abuse | 身份与权限越界 |
| ASI04 | Agentic Supply Chain | 动态加载的第三方组件被污染 |
| ASI05 | Unexpected Code Execution | 生成代码在非预期路径执行 |
| ASI06 | Memory & Context Poisoning | 记忆与上下文被投毒 |
| ASI07 | Insecure Inter-Agent Communication | 代理间消息可伪造/重放 |
| ASI08 | Cascading Failures | 单点故障沿信任链放大 |
| ASI09 | Human-Agent Trust Exploitation | 人类过度信任 Agent 输出 |
| ASI10 | Rogue Agents | Agent 偏离目标或授权范围 |

## 4. 两套清单的联合使用

同一事件常同时命中两边：

```text
"知识库文档里的隐藏指令让 Agent 发走数据"
→ LLM01（提示词注入）+ ASI01（目标劫持）
→ 硬约束缺失：摄入无来源标记 + 出站无白名单
```

**评估流程**：

1. 用 LLM Top 10 定位"模型/应用层"的问题。
2. 用 Agentic Top 10 定位"自主行为层"的问题。
3. 对每条命中，回到分层表（见 atk-assemble）确认是否有硬约束。
4. 只有软约束的条目进入整改清单。

## 5. 参考

- OWASP Top 10 for LLM Applications (2025)：https://genai.owasp.org/llm-top-10/
- OWASP Agentic AI Top 10 (2026)：https://genai.owasp.org/
