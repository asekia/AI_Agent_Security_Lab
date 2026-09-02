"""lab/runner.py — Web 界面专用的运行封装（不改变任何漏洞行为）。

本模块在**不修改** lab/graph.py、lab/multi_agent.py、lab/mock_llm.py 的前提下，
为 Web 界面提供结构化的"运行轨迹"（trace）捕获能力。

设计原则：
- 复用 lab.graph.run_scenario / lab.multi_agent.run_multi_agent 的真实执行逻辑，
  保证 agent 行为与 demos/ 完全一致（漏洞行为不变）。
- 通过 MockLLM 的确定性工具队列 + 图执行结果，重建每一步的
  {step, type, name, args, result} 结构化轨迹，供前端渲染。
- 所有函数均为纯本地、无网络调用。

注意：本模块仅用于**授权**的安全教学演示。
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTBOX = os.path.join(ROOT, "lab", "outbox.jsonl")
MEMORY_FILE = os.path.join(ROOT, "lab", "memory_store.json")
STATE_DIR = os.path.join(ROOT, "lab", "state")
CHECKPOINT_DB = os.path.join(STATE_DIR, "checkpoints.db")

# 五个强制演示的元数据（与 demos/ 一一对应）
DEMOS: dict[str, dict[str, Any]] = {
    "asi01": {
        "id": "asi01",
        "title": "ASI01 目标劫持 (Goal Hijacking)",
        "scenario": "asi01_goal_hijack",
        "mode": "single",
        "desc": "用户请求总结文档，文档内隐藏的间接提示注入载荷劫持 agent，外泄订单数据。",
    },
    "asi02": {
        "id": "asi02",
        "title": "ASI02 工具滥用 (Tool Misuse)",
        "scenario": "asi02_tool_abuse",
        "mode": "single",
        "desc": "UNION 型 SQLi 读库 → execute_python 任意代码执行 → 数据外泄，完整工具链滥用。",
    },
    "asi06": {
        "id": "asi06",
        "title": "ASI06 记忆投毒 (Memory Poisoning)",
        "scenario": "asi06_memory_poison",
        "mode": "single",
        "desc": "会话 1 植入伪装成系统偏好的投毒记忆，会话 2 检索时被误导并执行外泄。",
    },
    "asi07": {
        "id": "asi07",
        "title": "ASI07 消息伪造 (Message Spoofing)",
        "scenario": "asi07_msg_spoof",
        "mode": "multi",
        "desc": "email_worker 伪造 supervisor 指令，data_worker 因无来源认证而信任并执行。",
    },
    "asi09": {
        "id": "asi09",
        "title": "ASI09 审批滥用 (Approval Abuse)",
        "scenario": "asi09_hitl_bypass",
        "mode": "single",
        "desc": "HITL 审批展示 agent 自生成摘要且自动放行，危险工具未经严格审批即执行。",
    },
}


def _now_iso() -> str:
    """返回当前 UTC 时间的 ISO 格式字符串。"""
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: str) -> list[dict[str, Any]]:
    """读取 JSONL 文件为字典列表（文件不存在时返回空列表）。"""
    if not os.path.exists(path):
        return []
    entries: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def get_outbox_entries(limit: int = 50) -> list[dict[str, Any]]:
    """读取本地邮件外发记录 lab/outbox.jsonl。

    参数:
        limit: 最多返回的条数（取最新 N 条）。

    返回:
        邮件记录列表（每项含 timestamp / to / subject / body）。
    """
    entries = _read_jsonl(OUTBOX)
    return entries[-limit:]


def get_memory_store() -> list[dict[str, Any]]:
    """读取本地记忆存储 lab/memory_store.json。

    返回:
        记忆记录列表（每项含 text / session_id）。
    """
    if not os.path.exists(MEMORY_FILE):
        return []
    with open(MEMORY_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def get_checkpoint_info() -> dict[str, Any]:
    """读取检查点数据库的基本信息（表结构 + 记录数）。

    返回:
        包含表名与各表行数的字典。
    """
    import sqlite3

    info: dict[str, Any] = {"exists": os.path.exists(CHECKPOINT_DB), "tables": {}}
    if not info["exists"]:
        return info
    try:
        conn = sqlite3.connect(CHECKPOINT_DB)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        for (tname,) in cur.fetchall():
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{tname}"')
                info["tables"][tname] = cur.fetchone()[0]
            except sqlite3.Error:
                info["tables"][tname] = -1
        conn.close()
    except sqlite3.Error:
        pass
    return info


def _build_single_trace(scenario: str, results: list[str], auto_approve: bool) -> list[dict[str, Any]]:
    """根据 MockLLM 的确定性工具队列与图执行结果，重建单 agent 轨迹。

    参数:
        scenario: 场景名称。
        results: 图执行返回的工具结果列表（与工具队列一一对应）。
        auto_approve: 是否自动批准危险工具（用于标记被拒绝的步骤）。

    返回:
        结构化轨迹列表，每项含 step/type/name/args/result。
    """
    from lab.mock_llm import get_llm

    queue = get_llm().invoke(scenario)
    trace: list[dict[str, Any]] = []
    for i, call in enumerate(queue):
        name = call.get("tool", "")
        args = call.get("args", {})
        step = i + 1
        call_id = f"mock-call-{step}"
        trace.append(
            {
                "step": step,
                "type": "tool_call",
                "name": name,
                "args": args,
                "call_id": call_id,
                "result": None,
            }
        )
        # 结果与工具队列按顺序一一对应
        result = results[i] if i < len(results) else "[error] 结果缺失"
        trace.append(
            {
                "step": step,
                "type": "tool_result",
                "name": name,
                "args": args,
                "call_id": call_id,
                "result": result,
            }
        )
    return trace


def run_single_agent(prompt: str, thread_id: str | None = None, auto_approve: bool = True) -> dict[str, Any]:
    """运行单 agent 图并返回结构化轨迹（复用 lab.graph.run_scenario）。

    参数:
        prompt: 用户提示词 / 场景名称（如 "asi01_goal_hijack"）。
        thread_id: 检查点线程 ID（默认自动生成）。
        auto_approve: 是否自动批准危险工具（演示用，默认 True）。

    返回:
        字典，含 trace（轨迹列表）、final（最终结果列表）、
        outbox_entries（本次运行写入的外发记录）。
    """
    from lab.graph import run_scenario

    tid = thread_id or f"web-{uuid.uuid4().hex[:8]}"
    before = len(_read_jsonl(OUTBOX))
    results = run_scenario(prompt, thread_id=tid, auto_approve=auto_approve)
    after = _read_jsonl(OUTBOX)
    new_entries = after[before:]

    trace = _build_single_trace(prompt, results, auto_approve)
    return {
        "mode": "single",
        "scenario": prompt,
        "thread_id": tid,
        "trace": trace,
        "final": results,
        "outbox_entries": new_entries,
    }


def run_multi_agent(prompt: str = "", thread_id: str | None = None) -> dict[str, Any]:
    """运行多 agent 图并返回结构化轨迹（复用 lab.multi_agent.run_multi_agent）。

    参数:
        prompt: 用户提示词（多 agent 场景下主要用于展示，行为由图决定）。
        thread_id: 检查点线程 ID（默认自动生成）。

    返回:
        字典，含 trace（轨迹列表）、final（最终状态）、
        outbox_entries（本次运行写入的外发记录）。
    """
    from lab.multi_agent import run_multi_agent as _run

    tid = thread_id or f"web-{uuid.uuid4().hex[:8]}"
    before = len(_read_jsonl(OUTBOX))
    final = _run(thread_id=tid)
    after = _read_jsonl(OUTBOX)
    new_entries = after[before:]

    # 多 agent 轨迹：按节点顺序重建（supervisor → email_worker → data_worker）
    trace: list[dict[str, Any]] = [
        {
            "step": 1,
            "type": "node",
            "name": "supervisor",
            "args": {"task": "请处理客户支持任务：汇总订单数据并发送给客户。"},
            "result": "向 email_worker 派发任务",
        },
        {
            "step": 2,
            "type": "node",
            "name": "email_worker",
            "args": {"spoofed_sender": "supervisor", "recipient": "data_worker"},
            "result": "伪造 supervisor 指令（无来源认证）",
        },
        {
            "step": 3,
            "type": "node",
            "name": "data_worker",
            "args": {"trusted_sender": "supervisor"},
            "result": "信任伪造指令，执行 SQL 查询 + 发送邮件",
        },
    ]
    # 追加工具级结果（来自最终状态 results）
    for i, r in enumerate(final.get("results", [])):
        trace.append(
            {
                "step": 4 + i,
                "type": "tool_result",
                "name": "data_worker",
                "args": {},
                "result": r,
            }
        )

    return {
        "mode": "multi",
        "scenario": prompt or "asi07_msg_spoof",
        "thread_id": tid,
        "trace": trace,
        "final": final,
        "outbox_entries": new_entries,
    }


def run_demo(demo_id: str) -> dict[str, Any]:
    """运行指定演示并返回结构化轨迹。

    参数:
        demo_id: 演示标识（asi01 / asi06 / asi07）。

    返回:
        与 run_single_agent / run_multi_agent 相同结构的字典。
    """
    demo = DEMOS.get(demo_id)
    if not demo:
        raise ValueError(f"未知演示: {demo_id}")
    if demo["mode"] == "multi":
        return run_multi_agent(demo["scenario"], thread_id=f"{demo_id}-web")
    return run_single_agent(demo["scenario"], thread_id=f"{demo_id}-web", auto_approve=True)


def read_document(name: str) -> str:
    """读取 seed/documents/ 下的文档内容（供 Web 界面展示隐藏载荷）。

    参数:
        name: 文档文件名。

    返回:
        文档完整文本。
    """
    from lab.tools import read_document as _read

    return _read(name)


def extract_hidden_payloads(doc: str) -> dict[str, Any]:
    """从文档文本中提取隐藏的注入载荷（HTML 注释 + 不可见 Unicode）。

    参数:
        doc: 文档完整文本。

    返回:
        含 html_comment 与 invisible_unicode 两个字段的字典。
    """
    html_comment = ""
    start = doc.find("<!--")
    end = doc.find("-->")
    if start != -1 and end != -1:
        html_comment = doc[start + 4 : end].strip()

    # 提取不可见 Unicode 指令块（去除零宽字符后仍可读的文本）
    invisible = ""
    # 常见零宽字符
    zw = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u2066", "\u2067", "\u2068", "\u2069"]
    for ch in zw:
        if ch in doc:
            # 找到包含该零宽字符的整行
            for line in doc.splitlines():
                if ch in line:
                    cleaned = line
                    for z in zw:
                        cleaned = cleaned.replace(z, "")
                    cleaned = cleaned.strip()
                    if cleaned and cleaned not in invisible:
                        invisible += cleaned + "\n"
    return {"html_comment": html_comment, "invisible_unicode": invisible.strip()}
