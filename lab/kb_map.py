"""lab/kb_map.py — LLM 安全知识库分类的单一来源。

靶场最初只覆盖 OWASP Agentic AI Top 10（ASI01–ASI10）。LLM 安全本身的
知识体系（提示注入、编码混淆、越狱、模型与数据层攻击、上下文与记忆、
智能体、AI 基础设施与供应链、防御与评估、案例演练）此前散落在内部培训笔记里，
没有进入靶场，侧栏也无处可点。

本模块把这套体系收敛为唯一来源，供侧栏、知识库首页、分组页与文档页复用，
避免分类在各处各写一份而漂移。

结构:
- KB_GROUPS:  有序分组 (gid, 中文名, 英文名, 分组说明, [(slug, 标题, 英文名, 说明)])
- KB_DOCS:    slug -> {title, en, group, desc, file}
- KB_SOURCES: 官方参考来源（供首页展示）

运行时函数保持短名、无下划线: kbrows / kbgroup / kbdoc / kbstats。
"""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KBDIR = os.path.join(ROOT, "docs", "kb")

KB_GROUPS = [
    (
        "base",
        "基础与威胁建模",
        "Foundations & Threat Modeling",
        "先建立资产面、官方编号体系与威胁建模语言，后面每一类攻击才有可挂靠的框架。",
        [
            ("base-assets", "AI 资产面与威胁总表", "AI Asset Surface & Threat Table",
             "六类核心资产各自的威胁、攻击面、输入与后果。"),
            ("base-owasp", "OWASP LLM Top 10 (2025) 与 Agentic AI Top 10 (2026)",
             "OWASP LLM & Agentic Top 10",
             "两套官方编号体系，以及与本地靶场场景的对应关系。"),
            ("base-atlas", "MITRE ATLAS 技术矩阵与真实案例", "MITRE ATLAS Techniques & Cases",
             "官方 AML.Txxxx 技术编号、战术分组与已披露案例。"),
            ("base-stride", "STRIDE × AI 威胁建模", "STRIDE for AI",
             "把经典 STRIDE 六类映射到大模型应用的具体失效点。"),
            ("base-chain", "数据与模型供应链五阶段", "Data & Model Supply Chain",
             "从数据收集到推理的五个环节，以及各环节的投毒入口。"),
        ],
    ),
    (
        "inj",
        "提示注入体系",
        "Prompt Injection",
        "本靶场最核心的攻击族：从直接改写，到间接注入、结构化伪装与多步链路。",
        [
            ("inj-direct", "直接指令注入", "Direct Instruction Injection",
             "用户输入里直接改写目标、抢夺优先级或索取隐藏内容。"),
            ("inj-indirect", "间接注入与 RAG 注入", "Indirect & RAG Injection",
             "载荷藏在知识库、网页、文件、工具返回等模型会读取的数据里。"),
            ("inj-split", "多文档拆分注入", "Multi-Document Split Injection",
             "把攻击链拆到多份文档，让模型在拼接上下文时自行合成。"),
            ("inj-struct", "结构化格式注入", "Structured Format Injection",
             "把指令伪装成 JSON / YAML / tool_calls / metadata 字段。"),
            ("inj-spoof", "伪造轨迹与角色伪装", "Fake Trace & Role Spoofing",
             "伪造“已授权”的执行历史，或冒充 system / developer 消息层级。"),
            ("inj-defer", "延迟触发与条件链", "Deferred Trigger & Chained Steps",
             "正文看似无害，只在特定条件或多步推理中才触发。"),
            ("inj-tool", "工具滥用注入与敏感信息外带", "Tool Abuse & Exfiltration",
             "诱导真正调用工具，并把结果外带到答案、日志或固定输出格式。"),
            ("inj-output", "输出处理型攻击", "Improper Output Handling",
             "模型输出被下游危险渲染或执行的完整链路。"),
        ],
    ),
    (
        "obf",
        "编码混淆与扰动",
        "Obfuscation & Perturbation",
        "为绕过关键词与正则检测，对控制语句做字符级扰动与编码包装。",
        [
            ("obf-noise", "噪声分级与比例控制", "Noise Tiers & Ratios",
             "轻 / 中 / 强三级噪声，以及 10%–35% 的实战甜点区间。"),
            ("obf-unicode", "零宽字符、同形字与双向控制", "Zero-Width, Homoglyph & Bidi",
             "Unicode 归一化缺陷、混合脚本与双向覆盖字符的利用方式。"),
            ("obf-split", "Token 拆分、伪装拼写与分段拼接", "Token Splitting & Segmentation",
             "插空格符号换行、leet 变形、实体转义与跨段拼接。"),
            ("obf-mother", "母句设计与命中判定", "Mother Sentences & Success Criteria",
             "六类抽象母句、推荐组合顺序与四种判定结果。"),
        ],
    ),
    (
        "jail",
        "越狱与说服工程",
        "Jailbreak & Persuasion",
        "不直接要有害内容，而是用叙事、情感与多轮铺垫绕开对齐。",
        [
            ("jail-roleplay", "角色扮演越狱", "Roleplay Jailbreak",
             "把请求放进虚构叙事，让“规则不再适用”。"),
            ("jail-emotion", "情感诉求与说服技巧", "Emotional Appeal & Persuasion",
             "怀旧、共情、权威等说服路径，以及奶奶漏洞的运作机制。"),
            ("jail-multi", "多轮渐进式越狱", "Multi-Turn Crescendo",
             "信任建立、逐步升级、语境塑造、触发与回溯五种多轮手法。"),
            ("jail-auto", "自动化越狱：PAIR / TAP / GCG", "Automated Jailbreak",
             "三种代表性自动化攻击算法的原理、代价与差异。"),
        ],
    ),
    (
        "mod",
        "模型与数据层攻击",
        "Model & Data Attacks",
        "不攻击提示，而攻击模型本身与训练数据：抽取、反演、隐私与投毒。",
        [
            ("mod-extract", "模型提取与窃取", "Model Extraction & Stealing",
             "用大量 API 查询重建功能等价的替代模型。"),
            ("mod-invert", "模型反演", "Model Inversion",
             "从输出逆推训练数据中的属性与特征。"),
            ("mod-privacy", "成员推断与训练数据提取", "Membership Inference & Data Extraction",
             "判断样本是否参与训练，以及逐字还原记忆内容。"),
            ("mod-poison", "数据投毒与后门", "Data Poisoning & Backdoors",
             "训练期植入错误关联或触发式后门，验证集难以发现。"),
            ("mod-embed", "向量与嵌入弱点", "Vector & Embedding Weaknesses",
             "RAG 索引污染、跨租户检索泄露与嵌入反演。"),
        ],
    ),
    (
        "ctx",
        "上下文与记忆攻击",
        "Context & Memory Attacks",
        "针对上下文窗口本身：溢出、提示泄露与记忆投毒。",
        [
            ("ctx-overflow", "上下文窗口溢出", "Context Window Overflow",
             "利用 FIFO 缓冲特性把早期指令挤出窗口。"),
            ("ctx-leak", "系统提示泄露", "System Prompt Leakage",
             "套取系统提示，进而掌握检测规则与业务逻辑。"),
            ("ctx-memory", "记忆投毒与有状态对话操控", "Memory Poisoning & Stateful Manipulation",
             "在多轮对话中逐步写入长期生效的恶意信息。"),
        ],
    ),
    (
        "agt",
        "智能体与信任",
        "Agentic & Trust",
        "面向 Agent 的攻击面：权限、工具、多智能体协作与人的判断。",
        [
            ("agt-agency", "过度授权与工具误用", "Excessive Agency & Tool Misuse",
             "工具权限过大、边界不清导致的越权与副作用。"),
            ("agt-multi", "多智能体通信与级联故障", "Multi-Agent & Cascading Failures",
             "代理间缺乏来源校验，失败沿链路放大。"),
            ("agt-trust", "人机信任滥用与 AI 社会工程", "Human-Agent Trust Exploitation",
             "过度信任模型输出，以及 AI 驱动的社会工程。"),
        ],
    ),
    (
        "inf",
        "AI 基础设施与供应链",
        "AI Infrastructure & Supply Chain",
        "模型之外的真实攻击面：推理服务、MLOps 平台、向量库与依赖链。",
        [
            ("inf-finger", "推理服务器指纹识别", "Inference Server Fingerprinting",
             "端口、响应头、错误信息与端点命名四类指纹。"),
            ("inf-mlops", "MLOps 平台攻击面", "MLOps Platform Attack Surface",
             "MLflow / Kubeflow / Ray / Jupyter 的暴露面与攻击链。"),
            ("inf-vector", "向量数据库枚举", "Vector Database Enumeration",
             "集合、维度与元数据如何暴露业务与嵌入模型。"),
            ("inf-recon", "AI 基础设施侦察方法论", "AI Infrastructure Recon Methodology",
             "五个阶段与配套工具链，以及流量特征。"),
            ("inf-cve", "已知 CVE 清单", "Known CVE Reference",
             "推理框架与 MLOps 平台的公开漏洞速查。"),
            ("inf-defend", "检测签名与加固清单", "Detection Signatures & Hardening",
             "从防守方视角识别侦察，并给出可立即落地的收敛项。"),
        ],
    ),
    (
        "def",
        "防御与评估",
        "Defense & Evaluation",
        "把前面每一类攻击收敛成可落地的输入侧、架构侧与流程侧控制。",
        [
            ("def-input", "输入侧防御", "Input-Side Defenses",
             "归一化、指令边界、来源标记与检测策略。"),
            ("def-arch", "架构侧防御", "Architecture-Side Defenses",
             "最小权限、沙箱、出站管控与人工审批。"),
            ("def-test", "红队评测与上线清单", "Red Team Evaluation & Go-Live Checklist",
             "测试集设计、误报控制与上线自检项。"),
        ],
    ),
    (
        "case",
        "案例教材",
        "Case Studies & Drills",
        "把知识库落到具体对象上：以本 Agent 实例为例，完成一次可取证、可复评的安全自评。",
        [
            ("case-self", "案例：以本 Agent 实例为对象的安全自评", "Self-Assessment Case: This Agent",
             "对象画像、自评工具、9 项真实判定与逐条改进分析。"),
            ("case-chain", "案例推演：一条针对本 Agent 的完整攻击链", "Walkthrough: Full Attack Chain",
             "把薄弱点串成六阶段攻击链，并给出每一段的切断点。"),
            ("case-drill", "案例演练：自评流程与判定标准", "Drill: Procedure & Criteria",
             "取证、判定、改进、复评四步循环与判定标准。"),
        ],
    ),
]

# slug -> 文档元数据（由 KB_GROUPS 派生，避免两处维护）
KB_DOCS: dict[str, dict] = {}
for _gid, _gzh, _gen, _gdesc, _items in KB_GROUPS:
    for _slug, _title, _title_en, _desc in _items:
        KB_DOCS[_slug] = {
            "slug": _slug,
            "title": _title,
            "en": _title_en,
            "group": _gid,
            "group_zh": _gzh,
            "group_en": _gen,
            "desc": _desc,
            "file": os.path.join(KBDIR, _slug + ".md"),
        }

# 官方参考来源（供知识库首页展示）
KB_SOURCES = [
    ("OWASP Top 10 for LLM Applications (2025)", "https://genai.owasp.org/llm-top-10/"),
    ("OWASP Agentic AI Top 10", "https://genai.owasp.org/"),
    ("MITRE ATLAS", "https://atlas.mitre.org/"),
    ("NIST AI Risk Management Framework", "https://www.nist.gov/itl/ai-risk-management-framework"),
]


def kbrows() -> list[dict]:
    """按分组顺序返回全部文档元数据，用于知识库首页与侧栏统计。"""
    rows: list[dict] = []
    for gid, gzh, gen, gdesc, items in KB_GROUPS:
        for slug, title, title_en, desc in items:
            rows.append(
                {
                    "slug": slug,
                    "title": title,
                    "en": title_en,
                    "desc": desc,
                    "group": gid,
                    "group_zh": gzh,
                    "group_en": gen,
                }
            )
    return rows


def kbgroup(gid: str) -> dict | None:
    """按分组 id 返回分组元数据与文档列表；不存在时返回 None。"""
    for gid_, gzh, gen, gdesc, items in KB_GROUPS:
        if gid_ == gid:
            return {
                "id": gid_,
                "title": gzh,
                "en": gen,
                "desc": gdesc,
                "docs": [
                    {"slug": s, "title": t, "en": te, "desc": d} for s, t, te, d in items
                ],
            }
    return None


def kbdoc(slug: str) -> dict | None:
    """按 slug 返回单个文档元数据；不存在时返回 None。"""
    return KB_DOCS.get(slug)


def kbstats() -> tuple[int, int]:
    """返回 (分组数, 文档数)。"""
    return len(KB_GROUPS), len(KB_DOCS)
