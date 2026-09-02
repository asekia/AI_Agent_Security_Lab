# LangGraph 漏洞靶场 (langgraph-vuln-lab)

一个**刻意易受攻击**的 LangGraph Agentic 安全实验靶场，用于在完全本地、隔离的环境中练习
[OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
中的 **ASI01–ASI10**（Agentic Security 类别）。

> ⚠️ **安全警告**：本项目包含**故意引入的漏洞**，仅用于**授权**的红队训练、安全研究与面试演示。
> **切勿**将此靶场暴露到公网、生产环境或任何真实服务。所有 email / network 动作均为**本地模拟**，
> 不会产生任何真实网络调用。

---

## 1. 快速开始

### 环境要求
- Python **3.10+**（本项目在 3.12.9 上验证）
- Windows / macOS / Linux 均可

### 安装与运行

```powershell
# 1. 创建虚拟环境
python -m venv .venv

# 2. 激活（Windows PowerShell）
.\.venv\Scripts\Activate.ps1

# 3. 安装依赖（已固定版本）
pip install -r requirements.txt

# 4. 生成种子数据（文档 + SQLite 订单库）
python seed\seed_db.py

# 5. 运行冒烟测试（验证全部组件）
python smoke_test.py

# 6. 运行五个强制演示
python demos\asi01_goal_hijack.py
python demos\asi02_tool_abuse.py
python demos\asi06_memory_poison.py
python demos\asi07_msg_spoof.py
python demos\asi09_hitl_bypass.py

# 7. 运行 Agent 框架演示（LangChain/LangGraph，ASI01）
python demos\agent_asi01.py                # mock 后端，无防御（预期: 劫持成功）
python demos\agent_asi01.py --defense      # mock 后端 + 防御变体（预期: 未劫持）
```

> 默认 **mock 模式**：零 API key、零网络调用、完全离线、输出确定性。

---

## 2. 架构总览

```
                        ┌─────────────────────────────┐
                        │       用户 / 攻击者          │
                        └──────────────┬──────────────┘
                                       │ 请求
                                       ▼
        ┌──────────────────────────────────────────────────┐
        │              MockLLM (确定性, 离线)               │
        │   asi01_goal_hijack / asi02_tool_abuse /            │
        │   asi06_memory_poison / asi07_msg_spoof /           │
        │   asi09_hitl_bypass                                  │
        └──────────────────────────────────────────────────┘
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        │                        LangGraph 图                          │
        │                                                              │
        │   ┌──────────────┐        ┌──────────────────────────────┐  │
        │   │  单 Agent 图  │        │  多 Agent 图 (supervisor)    │  │
        │   │  agent_node   │        │  supervisor → email_worker  │  │
        │   │  + HITL       │        │            → data_worker    │  │
        │   └──────┬───────┘        └──────────────┬───────────────┘  │
        │          │                               │                  │
        │          ▼                               ▼                  │
        │   ┌────────────────────────────────────────────────────┐   │
        │   │              工具层 (lab/tools.py)                  │   │
        │   │  read_document / send_email / execute_python /     │   │
        │   │  query_orders (+ safe 变体)                         │   │
        │   └────────────────────────────────────────────────────┘   │
        │          │                               │                  │
        │          ▼                               ▼                  │
        │   ┌──────────────┐            ┌──────────────────────┐    │
        │   │  VectorMemory │            │  SqliteSaver 检查点   │    │
        │   │  (ASI06)      │            │  (持久化)             │    │
        │   └──────────────┘            └──────────────────────┘    │
        └──────────────────────────────────────────────────────────┘
                                       │
                                       ▼
        ┌──────────────────────────────────────────────────────────┐
        │  本地 Sink（全部本地，无网络）                              │
        │  lab/outbox.jsonl  ·  lab/state/checkpoints.db           │
        │  lab/memory_store.json  ·  seed/orders.db                │
        └──────────────────────────────────────────────────────────┘
```

---

## 3. ASI → 组件映射表

| ASI | 漏洞名称 | 组件 / 位置 | 漏洞注释 | 安全变体 |
|-----|----------|-------------|----------|----------|
| **ASI01** | 提示注入 (Prompt Injection) | `seed/documents/support_kb.md` 隐藏载荷 + `lab/graph.py` | `# [VULN] ASI01` | 输入净化 / 指令边界 |
| **ASI02** | 工具滥用 (Tool Misuse) | `lab/tools.py::send_email` | `# [VULN] ASI02` | `send_email_safe`（收件人白名单） |
| **ASI03** | 工具调用链劫持 (Tool Chaining) | `lab/graph.py::_execute_tool` | `# [VULN] ASI03` | 工具调用审计 |
| **ASI04** | 过度授权 (Over-Authorization) | `lab/tools.py::execute_python` | `# [VULN] ASI04` | 最小权限沙箱 |
| **ASI05** | 沙箱逃逸 (Sandbox Escape) | `lab/tools.py::execute_python` | `# [VULN] ASI05` | 受限执行环境 |
| **ASI06** | 记忆投毒 (Memory Poisoning) | `lab/memory.py::memory_search` | `# [VULN] ASI06` | `memory_search_scoped`（会话隔离） |
| **ASI07** | 消息伪造 (Message Spoofing) | `lab/multi_agent.py` | `# [VULN] ASI07` | 来源认证 / 消息签名 |
| **ASI08** | 无界消耗 (Unbounded Consumption) | `lab/multi_agent.py` | `# [VULN] ASI08` | `enforce_budget`（step 预算） |
| **ASI09** | 审批滥用 (Approval Abuse) | `lab/graph.py` HITL + demo 自动批准 | `# [VULN] ASI09` | 人工审批 + 摘要校验 |
| **ASI10** | 数据外泄 (Data Exfiltration) | `lab/tools.py::send_email` → `outbox.jsonl` | `# [VULN] ASI10` | 出站过滤 / 数据脱敏 |

---

## 4. 攻击面清单

| 攻击面 | 描述 | 演示 |
|--------|------|------|
| **间接提示注入** | 文档内含隐藏 HTML 注释 + 不可见 Unicode 指令块 | `asi01_goal_hijack.py` |
| **SQL 注入** | `query_orders` 使用字符串拼接 SQL | `smoke_test.py` |
| **无沙箱代码执行** | `execute_python` 直接 `exec` 用户输入 | 手动 |
| **跨会话记忆泄露** | `memory_search` 不按 session 隔离 | `asi06_memory_poison.py` |
| **多 agent 消息伪造** | worker 信任伪造的 supervisor 来源 | `asi07_msg_spoof.py` |
| **无界 token/step 消耗** | `token_budget` 字段未强制执行 | `asi07_msg_spoof.py` |
| **HITL 摘要信任** | demo 自动批准危险工具调用 | `asi01_goal_hijack.py` |

---

## 5. 运行说明

### Mock 模式（默认，推荐）
零配置、零网络、确定性输出：

```powershell
python demos\asi01_goal_hijack.py
python demos\asi06_memory_poison.py
python demos\asi07_msg_spoof.py
python smoke_test.py
```

### 真实 LLM 模式（可选）
通过环境变量启用（需自行提供 API key，**默认路径不需要**）：

```powershell
$env:LLM_PROVIDER = "openai"   # 或 anthropic
$env:LLM_API_KEY = "sk-..."
python demos\asi01_goal_hijack.py
```

> 真实模式会引入非确定性，且可能产生真实网络调用——**仅在你有意测试真实模型时使用**。

### Agent 框架真实后端（OpenAI 兼容端点）

`lab/framework` 的 Agent 通过任意 OpenAI 兼容端点接入真实 AI 模块
（OpenAI / DeepSeek / Ollama / vLLM / LM Studio 等），支持 function calling：

```powershell
$env:OPENAI_BASE_URL = "https://api.deepseek.com/v1"   # 或 http://localhost:11434/v1 (Ollama)
$env:LLM_API_KEY     = "sk-..."
$env:LAB_MODEL       = "deepseek-chat"
python demos\agent_asi01.py --backend real
```

> 真实模型对隐藏注入载荷的反应**不确定**（可能被劫持、也可能拒绝）——这正是
> 框架版相比脚本化 mock 的教学差异点：漏洞是否被触发由真实模型的行为决定。

### Web 模式（可选，推荐用于演示）
提供一个本地、离线的中文 Web 界面（DVWA/DVAIA 风格），用于查看漏洞映射表、运行攻击演示并查看结构化工具调用轨迹、在"游乐场"中输入自定义提示词、检查本地 sink、切换 mock / 真实 LLM 模式。

```powershell
# 1. 安装 Web 依赖（Flask）
pip install -r requirements.txt

# 2. 启动 Web 服务器（仅绑定 127.0.0.1）
python run_web.py

# 3. 浏览器打开
#    http://127.0.0.1:5000
```

> ⚠️ **安全**：Web 服务器**仅绑定 127.0.0.1**，绝不暴露到网络。所有资源均为本地（无外部 CDN）。真实 LLM 模式仅在 `/settings` 中显式开启时才会发起网络调用，且 API key 仅保存在进程内存（`os.environ`），**绝不写入磁盘**。

Web 界面页面：
- `/` 仪表盘：ASI01-ASI10 映射表 + 组件状态 + 快捷入口
- `/asi/<id>` 单个演示页（asi01 / asi02 / asi06 / asi07 / asi09）：运行并查看工具调用轨迹
- `/agent` **Agent 框架页**：场景选择（当前仅 ASI01 接入）+ mock/真实后端切换 + 防御变体开关 + 推理轨迹与劫持裁决
- `/playground` 游乐场：自定义提示词 + 单/多 Agent 模式 + 揭示隐藏注入载荷
- `/trace` 最近一次运行的完整轨迹
- `/log` 攻击历史（持久化到 `lab/web/run_log.jsonl`）
- `/settings` 切换 mock / 真实 LLM 模式

---

## 6. 目录结构

```
langgraph-vuln-lab/
├── requirements.txt          # 固定版本依赖
├── smoke_test.py             # 端到端冒烟测试
├── README.md                 # 本文档
├── lab/                      # 核心包
│   ├── __init__.py
│   ├── banner.py             # 启动横幅
│   ├── tools.py              # 工具集（含漏洞 + 安全变体）
│   ├── memory.py             # 向量记忆（ASI06）
│   ├── checkpointer.py       # SqliteSaver 持久化
│   ├── mock_llm.py           # 确定性 mock LLM（旧版脚本化）
│   ├── graph.py              # 单 Agent HITL 图（旧版）
│   ├── multi_agent.py        # 多 Agent supervisor 图（ASI07/08）
│   ├── framework/            # ★ Agent 框架（LangChain/LangGraph，真实 AI 接入）
│   │   ├── __init__.py       #    get_framework() 统一入口
│   │   ├── llm.py            #    BaseChatModel 后端（Mock / OpenAI 兼容真实）
│   │   ├── tools.py          #    langchain_core.tools 注册表 + 防御/审批包装
│   │   ├── agent.py          #    create_react_agent 封装 + 轨迹提取
│   │   ├── defenses.py       #    输入净化 + 指令边界（ASI01 对照）
│   │   └── registry.py       #    场景注册表（ASI01 wired，ASI02-10 stub）
│   ├── outbox.jsonl          # 本地邮件外发记录（运行时生成）
│   ├── memory_store.json     # 记忆存储（运行时生成）
│   └── state/                # 检查点数据库（运行时生成）
├── demos/                    # 可运行攻击演示
│   ├── asi01_goal_hijack.py
│   ├── asi06_memory_poison.py
│   ├── asi07_msg_spoof.py
│   └── agent_asi01.py        # ★ Agent 框架 ASI01 演示（--backend / --defense）
├── seed/                     # 种子数据
│   ├── seed_db.py            # 生成 orders.db
│   ├── orders.db             # SQLite 订单库
│   └── documents/            # 含隐藏注入载荷的文档
│       ├── quarterly_report.md
│       ├── employee_handbook.md
│       ├── product_roadmap.md
│       └── support_kb.md     # 含隐藏注入载荷
├── web/                      # Web 界面（Flask）
│   ├── app.py                # 路由 + JSON API（含 /agent 与 /principle）
│   ├── markdown.py           # 极简安全 Markdown 渲染（原理文档页）
│   ├── templates/            # 页面模板（含 agent.html / principle.html）
│   └── static/style.css      # 本地样式
├── docs/
│   └── asi01-principle.md    # ★ ASI01 原理与防护文档（成因/攻击链/纵深防御）
└── tests/                    # 单元测试（可选）
```

---

## 7. 防御侧（安全变体）

本项目不仅演示漏洞，还提供对应的**安全对照实现**，用于教学：

| 漏洞 | 安全变体 | 防御原理 |
|------|----------|----------|
| `send_email`（无收件人白名单） | `send_email_safe` | 收件人白名单 + 出站过滤 |
| `query_orders`（SQL 拼接） | `query_orders_safe` | 参数化查询 |
| `memory_search`（跨会话泄露） | `memory_search_scoped` | 按 session 隔离 |
| 多 agent 无来源认证 | （建议）消息签名 / 来源校验 | 认证 + 授权 |
| 无界消耗 | `enforce_budget` | step/token 预算强制 |
| HITL 信任摘要 | （建议）人工审批 + 摘要校验 | 关键操作人工确认 |

---

## 8. Agent 框架（LangChain / LangGraph 真实 AI 接入）

> 针对旧版"脚本化 MockLLM 脱节、无法接入真实 AI"的痛点，
> 靶场新增 `lab/framework/`：基于 **LangChain 官方抽象** 的标准 Agent 框架。
> 目前仅接入 **ASI01**，ASI02–ASI10 已占位（status=stub），可逐个扩展。

### 8.1 设计

```
                     ┌───────────────────────────────────────────────┐
                     │            lab/framework/  (Agent 框架)        │
 用户提示 ───────────▶│                                               │
                     │  llm.py      BaseChatModel 后端                │
                     │               ├─ MockChatModel（内容感知/离线） │
                     │               └─ OpenAICompatChatModel（真实）  │
                     │  tools.py    langchain_core.tools 注册表       │
                     │               （危险工具内嵌 interrupt = HITL） │
                     │  agent.py    create_react_agent（ReAct 循环）   │
                     │  defenses.py 输入净化 + 指令边界（ASI01 对照）   │
                     │  registry.py 场景注册表（ASI01 wired，其余 stub）│
                     └──────────────────────┬────────────────────────┘
                                            ▼
                    工具执行 → 文档内容 / 订单数据 / outbox.jsonl（本地）
```

- **模型即插即用**：两个后端都是 `langchain_core.language_models.chat_models.BaseChatModel`
  子类，可直接交给 `create_react_agent`。Mock 后端"内容感知"：读取文档后
  检测到隐藏注入载荷才被劫持（与真实模型的行为模式一致，但输出可复现）；
  真实后端通过 urllib 调用任意 OpenAI 兼容端点，支持 function calling，
  无 function calling 时回退解析 `{"tool": ..., "args": {...}}`。
- **真实 Agent 循环**：模型观察工具结果后自主决策下一步（ReAct），
  推理轨迹（思考 → 工具调用 → 结果 → 最终回答）全量可审计。
- **HITL 审批**：危险工具（send_email / execute_python）在工具内部调用
  `interrupt()` 请求人工审批（演示默认自动批准）。
- **防御对照**：`--defense` 开启 输入净化（剥离隐藏载荷）+ 指令边界系统提示
  + 收件人白名单（send_email_safe）。

### 8.2 运行

```powershell
# mock（离线、确定性）
python demos\agent_asi01.py
python demos\agent_asi01.py --defense

# 真实后端（OpenAI 兼容端点）
$env:OPENAI_BASE_URL = "https://api.deepseek.com/v1"
$env:LLM_API_KEY = "sk-..."
$env:LAB_MODEL = "deepseek-chat"
python demos\agent_asi01.py --backend real
```

或打开 Web 界面 `/agent` 页：选择场景 / 后端 / 防御开关，查看推理轨迹与劫持裁决。

**ASI01 原理与防护**（漏洞成因 + 防御纵深，含逐环节代码对应与对照实验）:
- 仓库文档: `docs/asi01-principle.md`
- Web 页面: `/principle/asi01`（导航栏"ASI01 原理"）

### 8.3 接入新场景（ASI02 等）

1. 在 `lab/framework/registry.py` 定义 `_build_asiXX(...)`，返回 agent 图（模型 + 工具集 + 系统提示）；
2. 注册 `ScenarioSpec(status="wired")`；
3. 前端 `/api/agent/scenarios` 与 `/agent` 页面自动出现新场景。

---

## 9. 免责声明

本项目**仅用于教育、研究与授权测试**。作者不对任何滥用行为负责。
使用前请确保你拥有对目标系统的**明确书面授权**。
