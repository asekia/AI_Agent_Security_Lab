# -*- coding: utf-8 -*-
"""lab/learn.py — 学习路径（把知识库串成有序阅读动线）。

每条路径是一串有序的阅读单元：每单元指出该看哪篇文档、重点看什么。
没有答题、没有判定、没有进度打卡——按顺序读完即完成。

函数命名保持短且无下划线: paths / getpath / unitrows / allrows。
"""
from __future__ import annotations

PATHS = [
    (
        "p1",
        "LLM 安全入门",
        "LLM Security Foundations",
        "从官方编号体系到第一次动手：理解风险面，打穿第一个不设防的 agent。",
        [
            ("p1-01", "read", "base-owasp",
             "读《OWASP LLM Top 10 (2025) 与 Agentic AI Top 10 (2026)》，两套编号体系各对应什么风险面。"),
            ("p1-03", "read", "ctx-overflow",
             "读《上下文窗口溢出》，理解 FIFO 缓冲特性如何把早期指令挤出窗口。"),
            ("p1-05", "read", "ctx-memory",
             "读《记忆投毒与有状态对话操控》，理解污染如何跨会话存活。"),
        ],
    ),
    (
        "p2",
        "提示注入与绕过实战",
        "Injection & Evasion in Practice",
        "注入的载体、伪装与绕过：从间接注入到编码混淆，逐档打穿净化与闸门。",
        [
            ("p2-01", "read", "inj-indirect",
             "读《间接注入与 RAG 注入》，重点看邮件转发规则的工作示例。"),
            ("p2-02", "read", "inj-split",
             "读《多文档拆分注入》，理解攻击为什么拆成多份反而更有效。"),
            ("p2-03", "read", "inj-struct",
             "读《结构化格式注入》，看指令如何伪装成数据格式。"),
            ("p2-04", "read", "obf-unicode",
             "读《零宽字符、同形字与双向控制》，理解 Unicode 处理缺陷如何被利用。"),
            ("p2-06", "read", "jail-multi",
             "读《多轮渐进式越狱》，看五类多轮手法如何绕过逐轮判定。"),
            ("p2-08", "read", "def-input",
             "读《输入侧防御》，理解净化为什么只能算第一层。"),
        ],
    ),
    (
        "p3",
        "AI 基础设施与纵深防御",
        "AI Infra & Defense in Depth",
        "模型之外的攻击面与防御分层：指纹、MLOps、供应链与「净化 + 闸门」两层的差距。",
        [
            ("p3-01", "read", "base-chain",
             "读《数据与模型供应链五阶段》，理解每个环节的投毒入口。"),
            ("p3-02", "read", "inf-finger",
             "读《推理服务器指纹识别》，掌握四类指纹与被动情报来源。"),
            ("p3-03", "read", "inf-mlops",
             "读《MLOps 平台攻击面》，走一遍 MLflow 五步枚举链。"),
            ("p3-05", "read", "inf-defend",
             "读《检测签名与加固清单》，从防守方视角复习侦察特征。"),
            ("p3-06", "read", "def-arch",
             "读《架构侧防御》，对照输入侧净化与输出侧闸门的分层位置。"),
        ],
    ),
]

_PATHS: dict[str, dict] = {}
for _pid, _zh, _en, _desc, _units in PATHS:
    _PATHS[_pid] = {"pid": _pid, "title": _zh, "en": _en, "desc": _desc, "units": _units}

# --------------------------------------------------------------- 查询接口

def allrows() -> list[dict]:
    """全部路径 + 单元数，供路径列表页使用。"""
    return [
        {"pid": p["pid"], "title": p["title"], "en": p["en"],
         "desc": p["desc"], "total": len(p["units"])}
        for p in _PATHS.values()
    ]

def getpath(pid: str) -> dict | None:
    """按 id 返回路径元数据；不存在返回 None。"""
    return _PATHS.get(pid)

def unitrows(pid: str) -> list[dict]:
    """路径下的全部单元，供详情页渲染。"""
    p = _PATHS.get(pid)
    if not p:
        return []
    return [
        {"uid": u[0], "slug": u[2], "task": u[3]}
        for u in p["units"]
    ]
