<div align="center">

# agent安全笔记

<img alt="tests" src="https://img.shields.io/badge/tests-52%20passing-brightgreen"> <img alt="python" src="https://img.shields.io/badge/python-3.12-blue"> <img alt="langgraph" src="https://img.shields.io/badge/LangGraph-1.2.11-purple"> <img alt="license" src="https://img.shields.io/badge/license-MIT-green">

</div>

AI Agent 安全知识库：10 篇 ASI 原理文档、50 篇分类知识文档、3 条学习路径。内容覆盖 OWASP Agentic AI Top 10 的逐项原理、攻击步骤、检测与防御。

## 目录

- [项目简介](#项目简介)
- [知识体系](#知识体系)
- [快速开始](#快速开始)
- [页面与用法](#页面与用法)
- [学习路径](#学习路径)
- [内容规范](#内容规范)
- [目录结构](#目录结构)
- [测试](#测试)
- [贡献](#贡献)
- [许可证](#许可证)
- [参考](#参考)

## 项目简介

本项目把 AI Agent 安全拆成可读、可查、可复现的两层：

| 层 | 内容 | 位置 |
| --- | --- | --- |
| 原理层 | OWASP Agentic AI Top 10（ASI01–ASI10）逐项原理、源码与防御 | `docs/asi01-principle.md` … `docs/asi10-principle.md` |
| 知识层 | 11 个分类、50 篇攻防文档，统一论文体结构 | `docs/kb/` |

> [!NOTE]
> 内容仅用于授权安全测试与防御建设。

## 知识体系

### ASI 主题（10 篇）

| 编号 | 主题 | 原理文档 |
| --- | --- | --- |
| ASI01 | 目标劫持 | `docs/asi01-principle.md` |
| ASI02 | 工具误用与利用 | `docs/asi02-principle.md` |
| ASI03 | 身份与权限滥用 | `docs/asi03-principle.md` |
| ASI04 | 代理供应链 | `docs/asi04-principle.md` |
| ASI05 | 意外代码执行 | `docs/asi05-principle.md` |
| ASI06 | 记忆与上下文投毒 | `docs/asi06-principle.md` |
| ASI07 | 不安全的代理间通信 | `docs/asi07-principle.md` |
| ASI08 | 级联代理故障 | `docs/asi08-principle.md` |
| ASI09 | 人机信任滥用 | `docs/asi09-principle.md` |
| ASI10 | 失控代理 | `docs/asi10-principle.md` |

### 分类知识库（11 组 / 50 篇）

| 分组 | 篇数 | 覆盖内容 |
| --- | --- | --- |
| 基础与威胁建模 | 5 | OWASP 两套编号、MITRE ATLAS、STRIDE、资产面、供应链五阶段 |
| 提示注入体系 | 8 | 直接/间接/拆分/结构化注入、伪造轨迹、延迟触发、工具外带、输出处理 |
| 编码混淆与扰动 | 4 | 噪声分级、Unicode 三类字符、token 拆分、母句设计 |
| 越狱与说服工程 | 4 | 角色扮演、情感诉求、多轮 Crescendo、PAIR/TAP/GCG |
| 模型与数据层攻击 | 5 | 模型提取、反演、成员推断、投毒、嵌入弱点 |
| 上下文与记忆攻击 | 3 | 上下文溢出、系统提示泄露、记忆投毒 |
| 智能体与信任 | 3 | 过度授权、多代理通信与级联、人机信任滥用 |
| AI 协议与运行时 | 5 | MCP 工具投毒、A2A 身份伪造、模型文件反序列化、多模态通道、编码绕过 |
| AI 基础设施与供应链 | 6 | 推理指纹、MLOps 枚举、向量库、侦察方法论、CVE、检测加固 |
| 防御与评估 | 3 | 输入侧防御、架构侧硬约束、红队评测与上线清单 |
| Agent 攻击面实战 | 4 | 提示词装配面、沙箱读写边界、权限面侦察、六阶段攻击链 |

## 快速开始

```bash
# 1. 创建虚拟环境
python -m venv .venv

# 2. 激活（Windows PowerShell）
.\.venv\Scripts\Activate.ps1

# 3. 安装依赖
pip install -r requirements.txt

# 4. 启动本地站点
python run_web.py
```

浏览器打开 `http://127.0.0.1:5000`。服务仅绑定回环地址。

> [!WARNING]
> 不要将本服务绑定到 `0.0.0.0` 或暴露到公网。所有场景均为教学用途。

## 页面与用法

| 路由 | 说明 |
| --- | --- |
| `/` | 仪表盘：学习路径入口 + ASI 主题矩阵 |
| `/learn` | 学习路径列表（3 条） |
| `/learn/<pid>` | 路径详情：有序阅读单元 |
| `/topic/<asi>` | ASI 主题整合页：原理全文 + 自动目录 + 相关知识库 |
| `/principle/<asi>` | 原理文档直连页 |
| `/kb` | 知识库总览（11 个分组） |
| `/kb/g/<gid>` | 分组页 |
| `/kb/<slug>` | 单篇文档（自动目录） |

## 学习路径

| 路径 | 单元数 | 动线 |
| --- | --- | --- |
| P1 LLM 安全入门 | 3 | 官方编号体系 → 上下文溢出 → 记忆投毒 |
| P2 提示注入与绕过实战 | 6 | 间接/拆分/结构化注入 → Unicode 缺陷 → 多轮越狱 → 净化的局限 |
| P3 AI 基础设施与纵深防御 | 5 | 供应链五阶段 → 推理指纹 → MLOps 枚举 → 检测签名 → 架构侧防御 |

## 内容规范

每篇知识文档按同一结构组织，便于横向对照：

```text
1. 问题与威胁模型      角色 / 能力 / 前提 + 核心命题
2. 原理推导            机制拆解与可推导结论
3. 攻击面与前提        入口 / 前提 / 观察点 / 影响
4. 实战步骤            编号步骤 + 载荷 + 预期 + 失败处理
5. 变体目录            编号 + 载荷要点 + 判定标记
6. 检测与取证          可观测信号 + 证据清单
7. 防御与验证          每项防御配实测验证方法
8. 参考                一手来源
```


## 目录结构

```text
.
├── run_web.py            # 本地站点入口
├── requirements.txt
├── smoke_test.py         # 端到端冒烟（10 项）
├── test_web.py           # 页面可达性与内容契约（42 项）
├── lab/                  # 核心实验实现
│   ├── asi_map.py        # ASI 名称与组件映射
│   ├── kb_map.py         # 知识库分组注册表
│   ├── learn.py          # 学习路径注册表
│   ├── graph.py          # 单 Agent 场景与 HITL
│   ├── multi_agent.py    # 多 Agent 与级联
│   ├── mock_llm.py       # 确定性场景队列
│   ├── tools.py          # 工具集（含安全对照）
│   ├── memory.py         # 向量记忆（含会话隔离）
│   └── runner.py         # 场景运行封装
├── docs/
│   ├── asi01-principle.md … asi10-principle.md
│   └── kb/               # 50 篇分类知识文档
├── seed/                 # 种子文档与订单库
└── web/                  # Flask 站点（路由 / 模板 / 静态资源）
```

## 测试

```bash
# 首次运行冒烟测试前生成种子数据库（web 页面本身不需要）
python seed/seed_db.py

python test_web.py       # 42 项：页面可达性、内容契约、已删功能无残留
python smoke_test.py     # 10 项：场景、工具、记忆、多 Agent 链路
```

## 贡献

- 技术内容以官方文档与公开研究为准；引用的 CVE/编号需可溯源。
- 提交前运行 `test_web.py` 与 `smoke_test.py`。
- 文档保持论文体结构，不写无信息量的过渡句。

## 许可证

本项目采用 [MIT License](LICENSE) 开源。

## 参考

- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
