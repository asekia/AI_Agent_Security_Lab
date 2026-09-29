"""lab/learn.py — 学习路径（TryHackMe 式教程层的注册表与判定）。

把知识库（读）、可动手靶场（练）串成有顺序、有进度、有客观判定的学习路径：

    单元类型
      read  读一篇知识库文档 → 回答验证题（答案来自文档内容）
      drill 完成一个靶场关卡（指定难度）→ 由 solves.has 自动判定
      quiz  独立验证题（用于收束一个阶段的理解）

判定原则
    每个单元都有客观判定，不靠"我读完了"的自评：
    read/quiz 靠答案匹配（归一化后与可接受答案比对），
    drill 靠 flag 通关记录（lab.solves），两者都不能被"点一下"跳过。

**测试隔离**：环境变量 LAB_LEARN 可覆盖进度文件路径（与 lab/solves.py 同约定）。

函数命名保持短且无下划线: paths / getpath / unitrows / submit / progress / allrows。
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "learn_progress.json")
ENV = "LAB_LEARN"

_PUNCT = re.compile(r"[\s\.,;:!\"'`()\[\]{}、，。；：？！（）《》\-—_]+")


def _norm(text: str) -> str:
    """答案归一化：小写、去空白与标点。"""
    return _PUNCT.sub("", (text or "").strip().lower())


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


def _save_done(done: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(progress_path()), exist_ok=True)
    with open(progress_path(), "w", encoding="utf-8") as f:
        json.dump({"done": done}, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------- 路径注册表
# 单元: (uid, kind, 参数…, 任务说明, 验证题, 可接受答案)
#   read:  (uid, "read",  kb_slug,  任务, 问题, [答案…])
#   drill: (uid, "drill", cid, level, 任务, 问题=None, [答案…]=None)
#   quiz:  (uid, "quiz",  问题, [答案…], 任务)

PATHS = [
    (
        "p1",
        "LLM 安全入门",
        "LLM Security Foundations",
        "从官方编号体系到第一次动手：理解风险面，打穿第一个不设防的 agent。",
        [
            ("p1-01", "read", "base-owasp",
             "读《OWASP LLM Top 10 (2025) 与 Agentic AI Top 10 (2026)》，两套编号体系各对应什么风险面。",
             "OWASP LLM Top 10 (2025) 排在 LLM01 的是什么风险？",
             ["提示注入", "promptinjection", "prompt injection"]),
            ("p1-02", "drill", "asi01", "low",
             "打靶场 asi01 的 low 档：不设防状态下直接写指令，让 agent 外发挑战秘密。"),
            ("p1-03", "read", "ctx-overflow",
             "读《上下文窗口溢出》，理解 FIFO 缓冲特性如何把早期指令挤出窗口。",
             "上下文溢出攻击利用了缓冲区的哪种行为？",
             ["fifo", "先入先出", "先进先出", "挤出最早", "丢弃最早", "最早的内容被丢弃"]),
            ("p1-04", "drill", "asi01", "medium",
             "打 asi01 的 medium 档：显式标记会被净化，换一种说法完成同一目标。"),
            ("p1-05", "read", "ctx-memory",
             "读《记忆投毒与有状态对话操控》，理解污染如何跨会话存活。",
             "记忆投毒与一次性注入的核心区别是什么？",
             ["跨会话", "持久", "多轮", "影响后续", "长期"]),
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
             "读《间接注入与 RAG 注入》，重点看邮件转发规则的工作示例。",
             "邮件转发示例中，攻击者诱导模型创建了什么？",
             ["转发规则", "create_email_forwarding_rule", "forwardingrule", "邮件转发规则"]),
            ("p2-02", "read", "inj-split",
             "读《多文档拆分注入》，理解攻击为什么拆成多份反而更有效。",
             "多文档拆分注入依赖模型的什么行为才能生效？",
             ["拼接", "合成", "聚合", "上下文合并", "拼接上下文", "自行合成"]),
            ("p2-03", "read", "inj-struct",
             "读《结构化格式注入》，看指令如何伪装成数据格式。",
             "结构化格式注入把指令伪装成哪类内容？",
             ["json", "yaml", "metadata", "元数据", "toolcall", "工具调用参数"]),
            ("p2-04", "read", "obf-unicode",
             "读《零宽字符、同形字与双向控制》，理解 Unicode 处理缺陷如何被利用。",
             "零宽字符与同形字利用的是哪类检测缺陷？",
             ["unicode", "归一化", "关键词匹配", "字符串匹配", "分词", "字面匹配"]),
            ("p2-05", "drill", "asi01", "medium",
             "打 asi01 的 medium 档：净化会剥离常见标记，用 P2 学到的载体换一种写法。"),
            ("p2-06", "read", "jail-multi",
             "读《多轮渐进式越狱》，看五类多轮手法如何绕过逐轮判定。",
             "Crescendo 类多轮攻击报告的成功率约为多少？",
             ["89", "89%", "约89"]),
            ("p2-07", "drill", "asi09", "low",
             "打 asi09 的 low 档：用无害摘要让危险动作通过人工审批。"),
            ("p2-08", "read", "def-input",
             "读《输入侧防御》，理解净化为什么只能算第一层。",
             "只有输入净化、没有出口管控的系统，为什么仍会被打穿？",
             ["可绕过", "绕过", "净化不是边界", "输出侧", "出口", "过滤不充分", "拦截不全"]),
        ],
    ),
    (
        "p3",
        "AI 基础设施与纵深防御",
        "AI Infra & Defense in Depth",
        "模型之外的攻击面与防御分层：指纹、MLOps、供应链，以及「净化 + 闸门」两层的差距。",
        [
            ("p3-01", "read", "base-chain",
             "读《数据与模型供应链五阶段》，理解每个环节的投毒入口。",
             "五个环节中，投毒影响最持久、最难修复的是哪个？",
             ["训练", "模型训练", "第三阶段", "第3阶段"]),
            ("p3-02", "read", "inf-finger",
             "读《推理服务器指纹识别》，掌握四类指纹与被动情报来源。",
             "哪个推理服务会在响应头里直接返回 GPU 利用率？",
             ["triton"]),
            ("p3-03", "read", "inf-mlops",
             "读《MLOps 平台攻击面》，走一遍 MLflow 五步枚举链。",
             "MLflow 枚举链的第一步调用哪个端点？",
             ["experimentssearch", "api/2.0/mlflow/experiments/search", "experiments/search"]),
            ("p3-04", "drill", "asi04", "low",
             "打 asi04 的 low 档：通过依赖清单引入一个带后门的包。"),
            ("p3-05", "read", "inf-defend",
             "读《检测签名与加固清单》，从防守方视角复习侦察特征。",
             "/metrics 端点只应允许哪个来源访问？",
             ["监控", "内部监控", "监控网段", "监控cidr", "monitoringcidr"]),
            ("p3-06", "read", "def-arch",
             "读《架构侧防御》，对照靶场 low/medium/high 三档的防御位置。",
             "本靶场 medium 可绕过、high 打不通，差距出在哪一层？",
             ["出口", "闸门", "输出侧", "egress", "gate", "出口管控", "闸门层"]),
            ("p3-07", "read", "def-test",
             "读《红队评测与上线清单》，理解误报为什么是评测的核心指标。",
             "评测集里「良性但相似」的样本用来测什么？",
             ["误报", "误报率", "过度拦截", "过度拦截率"]),
        ],
    ),
]

# slug 索引
_PATHS: dict[str, dict] = {}
for _pid, _zh, _en, _desc, _units in PATHS:
    _PATHS[_pid] = {"pid": _pid, "title": _zh, "en": _en, "desc": _desc, "units": _units}


# --------------------------------------------------------------- 查询接口

def allrows() -> list[dict]:
    """全部路径 + 各自的完成进度，供路径列表页使用。"""
    done = _load_done()
    rows = []
    for pid, p in _PATHS.items():
        total = len(p["units"])
        n = sum(1 for u in p["units"] if _unit_done(u, done))
        rows.append({"pid": pid, "title": p["title"], "en": p["en"],
                     "desc": p["desc"], "done": n, "total": total})
    return rows


def getpath(pid: str) -> dict | None:
    """按 id 返回路径元数据；不存在返回 None。"""
    return _PATHS.get(pid)


def unitrows(pid: str) -> list[dict]:
    """路径下的全部单元 + 状态，供详情页渲染。"""
    p = _PATHS.get(pid)
    if not p:
        return []
    done = _load_done()
    rows = []
    for u in p["units"]:
        uid, kind = u[0], u[1]
        row = {"uid": uid, "kind": kind, "done": _unit_done(u, done)}
        if kind == "read":
            row["slug"] = u[2]
            row["task"] = u[3]
            row["question"] = u[4]
        elif kind == "quiz":
            row["question"] = u[2]
            row["task"] = u[4] if len(u) > 4 else ""
        elif kind == "drill":
            row["cid"] = u[2]
            row["level"] = u[3]
            row["task"] = u[4]
            row["solved"] = _drill_done(u[2], u[3])
        rows.append(row)
    return rows


def _drill_done(cid: str, level: str) -> bool:
    from lab import solves
    return solves.has(cid, level)


def _unit_done(unit: tuple, done: dict[str, str]) -> bool:
    uid, kind = unit[0], unit[1]
    if kind == "drill":
        return _drill_done(unit[2], unit[3])
    return uid in done


# --------------------------------------------------------------- 提交判定

def submit(pid: str, uid: str, answer: str) -> dict:
    """提交一个 read/quiz 单元的答案；drill 单元不接受提交。

    返回 {ok, msg}；ok=True 时进度已记录。
    """
    p = _PATHS.get(pid)
    if not p:
        return {"ok": False, "msg": f"未知路径: {pid}"}
    unit = next((u for u in p["units"] if u[0] == uid), None)
    if not unit:
        return {"ok": False, "msg": f"未知单元: {uid}"}
    if unit[1] == "drill":
        return {"ok": False,
                "msg": "动手单元不在这里判定：去靶场关卡拿到 flag，进度会自动更新。"}
    accepted = unit[-1]
    got = _norm(answer)
    if not got:
        return {"ok": False, "msg": "答案不能为空。"}
    hit = any(a in got or got == _norm(a) for a in accepted)
    if not hit:
        return {"ok": False, "msg": "答案不符。回文档里找那句话，再试一次。"}
    done = _load_done()
    if uid not in done:
        done[uid] = datetime.now(timezone.utc).isoformat()
        _save_done(done)
    return {"ok": True, "msg": "判定通过，单元完成。"}
