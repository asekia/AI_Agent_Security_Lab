# agent安全笔记

可动手的 AI Agent 安全靶场：18 个关卡覆盖 **OWASP Agentic AI Top 10（ASI01–ASI10）** 与扩展攻击面，提交攻击载荷即可判定通关、取得 flag。默认离线运行，也可接入任意 OpenAI 兼容模型。

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

# 6. 逐项运行 10 个 OWASP 演示（ASI01–ASI10）
python demos\asi01_goal_hijack.py
python demos\asi02_tool_abuse.py
python demos\asi03_priv_abuse.py
python demos\asi04_supply_chain.py
python demos\asi05_code_exec.py
python demos\asi06_memory_poison.py
python demos\asi07_msg_spoof.py
python demos\asi08_cascade.py
python demos\asi09_hitl_bypass.py
python demos\asi10_rogue_agent.py

# 7. 运行 Agent 框架演示（LangChain/LangGraph，ASI01）
python demos\agent_asi01.py                # mock 后端，无防御（预期: 劫持成功）
python demos\agent_asi01.py --defense      # mock 后端 + 防御变体（预期: 未劫持）
```

---

## 2. 架构总览

```
                        ┌─────────────────────────────┐
                        │       用户 / 攻击者          │
                        └──────────────┬──────────────┘
                                       │ 请求
                                       ▼
        ┌──────────────────────────────────────────────────┐
        │              MockLLM（默认，确定性）               │
        │   10 个 ASI 场景由统一 Runner 执行            │
        │   单 Agent / 多 Agent / 级联 Agent           │
        │   OpenAI 兼容真实 LLM（可选）                    │
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
        │  本地 Sink（邮件结果与运行状态）                              │
        │  lab/outbox.jsonl  ·  lab/state/checkpoints.db           │
        │  lab/memory_store.json  ·  seed/orders.db                │
        └──────────────────────────────────────────────────────────┘
```

---

## 3. ASI → 组件映射表（命名对齐 OWASP Agentic AI Top 10 · 2026）

> ASI 编号有新旧草案之分，下表以 **OWASP 2026 官方定义**为准。

| ASI | 漏洞名称 (2026 官方) | 组件 / 位置 | 漏洞注释 | 安全变体 |
|-----|----------------------|-------------|----------|----------|
| **ASI01** | 目标劫持 (Agent Goal Hijacking · 经间接提示注入) | `seed/documents/*.md` 隐藏载荷 + `lab/graph.py` / `lab/framework` | `# [VULN] ASI01` | 输入净化 / 指令边界 |
| **ASI02** | 工具误用与利用 (Tool Misuse & Exploitation) | `lab/tools.py::query_orders / execute_python / send_email` | `# [VULN] ASI02` | `query_orders_safe`（参数化）/ `send_email_safe`（收件人白名单） |
| **ASI03** | 身份与权限滥用 (Identity & Privilege Abuse) | `lab/tools.py::execute_python`（会话内提权冒充） | `# [VULN] ASI03` | 最小权限工具集 / 会话身份隔离 |
| **ASI04** | 代理供应链 (Agentic Supply Chain) | `seed/documents/rules.md` + `lab/tools.py::read_document` | `# [VULN] ASI04` | 规则 / 依赖来源签名 + 供应链锁定 |
| **ASI05** | 意外代码执行 (Unexpected Code Execution) | `lab/tools.py::execute_python` | `# [VULN] ASI05` | 受限沙箱 + 资源限制 |
| **ASI06** | 记忆与上下文投毒 (Memory & Context Poisoning) | `lab/memory.py::memory_search` | `# [VULN] ASI06` | `memory_search_scoped`（会话隔离） |
| **ASI07** | 不安全的代理间通信 (Insecure Inter-Agent Communication) | `lab/multi_agent.py` | `# [VULN] ASI07` | 来源认证 / 消息签名 |
| **ASI08** | 级联代理故障 (Cascading Agent Failures) | `lab/multi_agent.py`（多级 worker 传播, `asi08_cascade`） | `# [VULN] ASI08` | 独立预算 + 失败熔断 + 输出二次校验 |
| **ASI09** | 人机信任滥用 (Human-Agent Trust Exploitation) | `lab/graph.py` HITL + demo 自动批准 | `# [VULN] ASI09` | 人工审批 + 摘要与动作双向绑定 + 二次确认 |
| **ASI10** | 失控代理 (Rogue Agents) | `lab/tools.py::send_email` → `outbox.jsonl`（越界自主行为） | `# [VULN] ASI10` | 出站管控 / 会话级行为边界 |

---

## 4. 攻击面清单

| 攻击面 | 描述 | 演示 |
|--------|------|------|
| **间接提示注入 → 目标劫持** (ASI01) | 文档内含隐藏 HTML 注释 + 不可见 Unicode 指令块 | `asi01_goal_hijack.py` |
| **工具误用与利用** (ASI02) | `query_orders` 字符串拼接 SQL + `execute_python` 任意执行 + 外泄 | `asi02_tool_abuse.py` |
| **身份与权限滥用** (ASI03) | agent 以提升身份越权读取订单 | `asi03_priv_abuse.py` |
| **代理供应链** (ASI04) | 第三方 `rules.md` 规则包被污染，未经校验即采用 | `asi04_supply_chain.py` |
| **意外代码执行** (ASI05) | `execute_python` 无沙箱执行宿主命令 | `asi05_code_exec.py` |
| **跨会话记忆投毒** (ASI06) | `memory_search` 不按 session 隔离 | `asi06_memory_poison.py` |
| **不安全代理间通信 · 消息伪造** (ASI07) | worker 信任伪造的 supervisor 来源 | `asi07_msg_spoof.py` |
| **级联代理故障** (ASI08) | 上游未验证断言沿信任链放大为越权 | `asi08_cascade.py` |
| **人机信任滥用 · HITL** (ASI09) | demo 自动批准危险工具调用 | `asi09_hitl_bypass.py` |
| **失控代理** (ASI10) | agent 越界自主外泄内部数据 | `asi10_rogue_agent.py` |

---

## 5. 运行说明

### Mock 模式（默认）
无需 API key，输出确定。

```powershell
python demos\asi01_goal_hijack.py
python demos\asi03_priv_abuse.py
python demos\asi04_supply_chain.py
python demos\asi05_code_exec.py
python demos\asi08_cascade.py
python demos\asi10_rogue_agent.py
python smoke_test.py
```

### 真实 LLM 模式（可选）
通过环境变量启用：

```powershell
$env:LLM_PROVIDER = "openai"   # 或 anthropic
$env:LLM_API_KEY = "sk-..."
python demos\asi01_goal_hijack.py
```

> 真实模式输出不确定，并会产生真实网络调用。

### Agent 框架真实后端（OpenAI 兼容端点）

`lab/framework` 的 Agent 通过任意 OpenAI 兼容端点接入真实 AI 模块
（OpenAI / DeepSeek / Ollama / vLLM / LM Studio 等），支持 function calling：

```powershell
$env:OPENAI_BASE_URL = "https://api.deepseek.com/v1"   # 或 http://localhost:11434/v1 (Ollama)
$env:LLM_API_KEY     = "sk-..."
$env:LAB_MODEL       = "deepseek-chat"
python demos\agent_asi01.py --backend real
```

> 真实模型对注入载荷的反应不确定：可能被劫持，也可能拒绝。

### 水印对抗实验（离线可跑，不发 flag）

`lab/watermark` 提供水印窃取 / 伪造 / 清洗的可测量实验，输出对照矩阵与曲线：

```powershell
# 对照矩阵（TPR@FPR、保真度、窃取成本与规则质量）
python -c "from lab.watermark import lab; r=lab.run(reps=12, n=200); print(r['watermarked']['tpr'], r['scrubbed']['tpr'])"

# 改写预算扫描：同等预算下，朴素改写 vs 增强清洗
python -c "from lab.watermark import lab; [print('%.0f%% naive=%.2f scrub=%.2f' % (x['frac']*100, x['naive']['tpr'], x['scrub']['tpr'])) for x in lab.sweep()['rows']]"

# 防御实测：限流 / 密钥轮换 / 输出扰动对窃取与伪造的真实数字
python -c "from lab.watermark import defend; import json; print(json.dumps(defend.allthree(reps=24, n=200, n_query=40), ensure_ascii=False, default=str))"

# 方案族对比：上下文依赖表 vs 单表（窃取成本差 148 倍，清洗存活率相反）
python -c "from lab.watermark import lab; d=lab.schemecmp(reps=12, n=200, n_query=40); print(d['queries'], d['bigram']['scrubbed']['tpr'], d['unigram']['scrubbed']['tpr'])"

# 回归测试（88 项：仪器检查 / 攻击有效性 / 公平对照 / 编排层 / 防御与边界 / 方案族）
python test_watermark.py
```

> 水印结论依赖 FPR 与文本长度，用"过/不过"表示会掩盖前提，因此采用测量制。

### Web 模式
本地、离线的中文 Web 界面（DVWA/DVAIA 风格）：

```powershell
# 1. 安装 Web 依赖（Flask）
pip install -r requirements.txt

# 2. 启动 Web 服务器（仅绑定 127.0.0.1）
python run_web.py

# 3. 浏览器打开
#    http://127.0.0.1:5000
```

Web 界面页面：
- `/` 仪表盘：学习路径进度 + ASI 主题矩阵 + 组件状态
- `/learn` **学习路径**：3 条路径 21 个单元（读文档 / 打关卡 / 验证题，全部客观判定）
- `/topic/<asi>` **ASI 主题整合页**：原理全文 + 目录 + 动手关卡 + 相关知识
- `/arena` **可动手靶场**：18 个关卡（ASI01–ASI10 + MCP / A2A / 向量库 / 模型文件 / 多模态 / 护栏 / 推理服务 / 自治），每关 low / medium / high 三档，提交攻击载荷判定通关并发放 flag
- `/asi/<id>` 单个演示页（asi01 / asi02 / asi06 / asi07 / asi09）：运行并查看工具调用轨迹
- `/agent` **Agent 框架页**：场景选择（当前仅 ASI01 接入）+ mock/真实后端切换 + 防御变体开关 + 推理轨迹与劫持裁决
- `/asi01/chat` ASI01 对话：与真实模型多轮对话，观察真实注入行为
- `/playground` 游乐场：自定义提示词 + 单/多 Agent 模式 + 揭示隐藏注入载荷
- `/kb` 知识库：53 篇攻防文档（按分组浏览）
- `/selfaudit` 自评：以本机 Agent 实例为对象的一键自评
- `/watermark` **水印对抗实验**：水印 → 窃取 → 伪造 → 清洗的对照矩阵、预算扫描与防御实测（测量页，不发 flag）
- `/trace` 最近一次运行的完整轨迹
- `/log` 攻击历史（持久化到 `lab/web/run_log.jsonl`）
- `/settings` mock / 真实 LLM 模式切换与 key 管理

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
│   ├── mock_llm.py           # 确定性 mock LLM
│   ├── graph.py              # 单 Agent HITL 图
│   ├── multi_agent.py        # 多 Agent supervisor 图（ASI07/08）
│   ├── framework/            # ★ Agent 框架（LangChain/LangGraph，真实 AI 接入）
│   │   ├── __init__.py       #    get_framework() 统一入口
│   │   ├── llm.py            #    BaseChatModel 后端（Mock / OpenAI 兼容真实）
│   │   ├── tools.py          #    langchain_core.tools 注册表 + 防御/审批包装
│   │   ├── agent.py          #    create_react_agent 封装 + 轨迹提取
│   │   ├── defenses.py       #    输入净化 + 指令边界（ASI01 对照）
│   │   └── registry.py       #    场景注册表（ASI01 wired，ASI02-10 stub）
│   ├── arena.py              # ★ 靶场核心：18 关 spec、4 阶段判定、三档难度
│   ├── flags.py              # ★ flag 签发与校验（HMAC-SHA256，key 见 .flagkey）
│   ├── kb_map.py             # ★ 知识库分组与文档权威来源（/kb 侧栏）
│   ├── levels.py             # 难度档位定义
│   ├── asi_map.py            # ASI01–ASI10 与组件的映射表
│   ├── selfaudit.py          # 自评：以本机 Agent 实例为对象
│   ├── llmconf.py            # LLM 配置本机持久化（key 默认不落盘）
│   ├── solves.py             # 通关记录
│   ├── watermark/            # ★ 水印对抗实验样本（测量制，不发 flag）
│   │   ├── kgw.py            #    KGW 绿名单水印内核（PRF + z 检验）
│   │   ├── attack.py         #    窃取 / 伪造 / 清洗 / 对照组
│   │   ├── defend.py         #    防御实测：限流 / 密钥轮换 / 输出扰动
│   │   └── lab.py            #    指标与编排（run / sweep / lencur / schemecmp）
│   ├── outbox.jsonl          # 本地邮件外发记录（运行时生成）
│   ├── memory_store.json     # 记忆存储（运行时生成）
│   └── state/                # 检查点数据库（运行时生成）
├── demos/                    # 可运行攻击演示（ASI01–ASI10）
│   ├── asi01_goal_hijack.py   # ASI01 目标劫持（间接提示注入）
│   ├── asi02_tool_abuse.py    # ASI02 工具误用与利用
│   ├── asi03_priv_abuse.py    # ASI03 身份与权限滥用
│   ├── asi04_supply_chain.py  # ASI04 代理供应链
│   ├── asi05_code_exec.py     # ASI05 意外代码执行
│   ├── asi06_memory_poison.py # ASI06 记忆与上下文投毒
│   ├── asi07_msg_spoof.py     # ASI07 不安全代理间通信（消息伪造）
│   ├── asi08_cascade.py       # ASI08 级联代理故障
│   ├── asi09_hitl_bypass.py   # ASI09 人机信任滥用（HITL 绕过）
│   ├── asi10_rogue_agent.py   # ASI10 失控代理
│   └── agent_asi01.py        # ★ Agent 框架 ASI01 演示（--backend / --defense）
├── seed/                     # 种子数据
│   ├── seed_db.py            # 生成 orders.db
│   ├── orders.db             # SQLite 订单库
│   └── documents/            # 含隐藏注入载荷的文档
│       ├── quarterly_report.md
│       ├── employee_handbook.md
│       ├── product_roadmap.md
│       ├── rules.md          # 被污染的"第三方规则包"（ASI04 供应链演示）
│       └── support_kb.md     # 含隐藏注入载荷（ASI01）
├── web/                      # Web 界面（Flask）
│   ├── app.py                # 路由 + JSON API
│   ├── markdown.py           # 极简安全 Markdown 渲染（原理文档页）
│   ├── templates/            # 页面模板
│   └── static/style.css      # 本地样式
├── docs/
│   ├── kb/                   # 知识库 53 篇（基础/注入/混淆/越狱/模型/上下文/智能体/协议/基础设施/防御/案例）
│   ├── asi01-principle.md    # ★ ASI01 原理与防护文档（成因/攻击链/纵深防御）
│   ├── asi02-principle.md    # ★ ASI02-ASI10 原理与防护文档（写法与 ASI01 一致）
│   ├── asi03-principle.md
│   ├── asi04-principle.md
│   ├── asi05-principle.md
│   ├── asi06-principle.md
│   ├── asi07-principle.md
│   ├── asi08-principle.md
│   ├── asi09-principle.md
│   └── asi10-principle.md
└── test_arena.py             # 靶场测试（158 项，另见 test_web / test_llm / test_watermark / smoke_test）
```

---

## 7. 防御侧（安全变体）

安全对照实现：

| 漏洞 | 安全变体 | 防御原理 |
|------|----------|----------|
| `send_email`（无收件人白名单） | `send_email_safe` | 收件人白名单 + 出站过滤 |
| `query_orders`（SQL 拼接） | `query_orders_safe` | 参数化查询 |
| `memory_search`（跨会话泄露） | `memory_search_scoped` | 按 session 隔离 |
| 多 agent 无来源认证 (ASI07) | （建议）消息签名 / 来源校验 | 认证 + 授权 |
| 级联代理故障 (ASI08) | （建议）独立预算/熔断 + 输出校验 | 每 worker 独立防护 + 二次校验 |
| HITL 信任摘要 (ASI09) | （建议）人工审批 + 摘要校验 | 关键操作人工确认 |
| 失控代理 (ASI10) | （建议）会话级边界 + 出站策略 | 越界动作检测与熔断 |

---

## 8. Agent 框架（LangChain / LangGraph 真实 AI 接入）

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
# mock（确定性）
python demos\agent_asi01.py
python demos\agent_asi01.py --defense

# 真实后端（OpenAI 兼容端点）
$env:OPENAI_BASE_URL = "https://api.deepseek.com/v1"
$env:LLM_API_KEY = "sk-..."
$env:LAB_MODEL = "deepseek-chat"
python demos\agent_asi01.py --backend real
```

或打开 Web 界面 `/agent` 页：选择场景 / 后端 / 防御开关，查看推理轨迹与劫持裁决。

**ASI01–ASI10 原理与防护**（每篇含漏洞成因 + 攻击链解析 + 纵深防御，逐环节代码对应与对照实验）:

| ASI | 仓库文档 | Web 页面 |
|-----|---------|---------|
| ASI01 目标劫持 | `docs/asi01-principle.md` | `/principle/asi01` |
| ASI02 工具误用与利用 | `docs/asi02-principle.md` | `/principle/asi02` |
| ASI03 身份与权限滥用 | `docs/asi03-principle.md` | `/principle/asi03` |
| ASI04 代理供应链 | `docs/asi04-principle.md` | `/principle/asi04` |
| ASI05 意外代码执行 | `docs/asi05-principle.md` | `/principle/asi05` |
| ASI06 记忆与上下文投毒 | `docs/asi06-principle.md` | `/principle/asi06` |
| ASI07 不安全的代理间通信 | `docs/asi07-principle.md` | `/principle/asi07` |
| ASI08 级联代理故障 | `docs/asi08-principle.md` | `/principle/asi08` |
| ASI09 人机信任滥用 | `docs/asi09-principle.md` | `/principle/asi09` |
| ASI10 失控代理 | `docs/asi10-principle.md` | `/principle/asi10` |

### 8.3 接入新场景（ASI02 等）

1. 在 `lab/framework/registry.py` 定义 `_build_asiXX(...)`，返回 agent 图（模型 + 工具集 + 系统提示）；
2. 注册 `ScenarioSpec(status="wired")`；
3. 前端 `/api/agent/scenarios` 与 `/agent` 页面自动出现新场景。

---

## 9. 免责声明

本项目**仅用于教育、研究与授权测试**。作者不对任何滥用行为负责。
使用前请确保你拥有对目标系统的**明确书面授权**。

---

## 10. 参考资料

- [OWASP GenAI Security Project — Agentic AI Top 10（ASI01–ASI10）](https://genai.owasp.org/)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [Model Context Protocol（MCP）](https://modelcontextprotocol.io/)
- [Agent2Agent Protocol（A2A）](https://a2a-protocol.org/)
- [LangGraph 文档](https://docs.langchain.com/oss/python/langgraph/overview)
