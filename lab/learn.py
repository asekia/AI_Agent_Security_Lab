# -*- coding: utf-8 -*-
"""lab/learn.py — 学习路径（把知识库与靶场串成有序动线）。

设计：每条路径是一串有序单元，只有两种——
    read   读一篇知识库文档（给出该看什么）
    drill  打一个靶场关卡（flag 签发即自动完成）
没有答题、没有自评按钮：进度只由真实动作（拿到 flag）驱动。

**测试隔离**：环境变量 LAB_LEARN 可覆盖进度文件路径（与 lab/solves.py 同约定）。

函数命名保持短且无下划线: paths / getpath / unitrows / progress / allrows。
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "learn_progress.json")
ENV = "LAB_LEARN"


def progress_path() -> str:
    """返回进度文件路径（每次调用都读环境变量，便于测试隔离）。"""
    return os.environ.get(ENV) or DEFAULT


def _load_done() -> dict[str, str]:
    if not os.path.exists(progress_path()):
        return {}
    try:
        with open(progress_path(), "r", encoding="utf-8") as f:
            return json.load(f).get("done", {})
    except (json.JSONDecodeError, OSError):
        return {}


# --------------------------------------------------------------- 路径注册表
# 单元: (uid, kind, 参数, 任务说明)
#   read:  (uid, "read",  kb_slug, 任务)
#   drill: (uid, "drill", cid, level, 任务)

PATHS = [
    (
        "p1",
        "LLM 安全入门",
        "LLM Security Foundations",
        "从官方编号体系到第一次动手：理解风险面，打穿第一个不设防的 agent。",
        [
            ("p1-01", "read", "base-owasp",
             "读《OWASP LLM Top 10 (2025) 与 Agentic AI Top 10 (2026)》，两套编号体系各对应什么风险面。"),
            ("p1-02", "drill", "asi01", "low",
             "打靶场 asi01 的 low 档：不设防状态下直接写指令，让 agent 外发挑战秘密。"),
            ("p1-03", "read", "ctx-overflow",
             "读《上下文窗口溢出》，理解 FIFO 缓冲特性如何把早期指令挤出窗口。"),
            ("p1-04", "drill", "asi01", "medium",
             "打 asi01 的 medium 档：显式标记会被净化，换一种说法完成同一目标。"),
            ("p1-05", "read", "ctx-memory",
             "读《记忆投毒与有状态对话操控》，理解污染如何跨会话存活。"),
            ("p1-06", "drill", "asi06", "low",
             "打 asi06 的 low 档：把一条会影响后续会话的规则写进长期记忆。"),
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
            ("p2-05", "drill", "asi01", "medium",
             "打 asi01 的 medium 档：净化会剥离常见标记，用前面学到的载体换一种写法。"),
            ("p2-06", "read", "jail-multi",
             "读《多轮渐进式越狱》，看五类多轮手法如何绕过逐轮判定。"),
            ("p2-07", "drill", "asi09", "low",
             "打 asi09 的 low 档：用无害摘要让危险动作通过人工审批。"),
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
            ("p3-04", "drill", "asi04", "low",
             "打 asi04 的 low 档：通过依赖清单引入一个带后门的包。"),
            ("p3-05", "read", "inf-defend",
             "读《检测签名与加固清单》，从防守方视角复习侦察特征。"),
            ("p3-06", "read", "def-arch",
             "读《架构侧防御》，对照靶场 low/medium/high 三档的防御位置。"),
        ],
    ),
]

_PATHS: dict[str, dict] = {}
for _pid, _zh, _en, _desc, _units in PATHS:
    _PATHS[_pid] = {"pid": _pid, "title": _zh, "en": _en, "desc": _desc, "units": _units}


# --------------------------------------------------------------- 查询接口

def _drill_done(cid: str, level: str) -> bool:
    from lab import solves
    return solves.has(cid, level)


def allrows() -> list[dict]:
    """全部路径 + 完成进度，供路径列表页使用。"""
    rows = []
    for pid, p in _PATHS.items():
        drills = [u for u in p["units"] if u[1] == "drill"]
        n = sum(1 for u in drills if _drill_done(u[2], u[3]))
        rows.append({"pid": pid, "title": p["title"], "en": p["en"],
                     "desc": p["desc"], "done": n, "total": len(drills)})
    return rows


def getpath(pid: str) -> dict | None:
    """按 id 返回路径元数据；不存在返回 None。"""
    return _PATHS.get(pid)


def unitrows(pid: str) -> list[dict]:
    """路径下的全部单元 + 状态，供详情页渲染。"""
    p = _PATHS.get(pid)
    if not p:
        return []
    rows = []
    for u in p["units"]:
        uid, kind = u[0], u[1]
        row = {"uid": uid, "kind": kind, "task": u[-1]}
        if kind == "read":
            row["slug"] = u[2]
        else:
            row["cid"] = u[2]
            row["level"] = u[3]
            row["done"] = _drill_done(u[2], u[3])
        rows.append(row)
    return rows
