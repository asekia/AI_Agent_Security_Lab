"""lab/graph.py — 单 agent 图定义（ASI01/ASI06/ASI09 攻击面）。

构建一个带持久化检查点与 HITL 审批的单 agent 图：
- agent_node: 从 MockLLM 获取工具调用序列并逐个执行
- 危险工具（send_email / execute_python）经 interrupt() 审批节点
- 使用 SqliteSaver 持久化状态（ASI06 + 框架层 RCE 讨论）
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from lab import tools
from lab.checkpointer import get_checkpointer
from lab.mock_llm import get_llm

DANGEROUS_TOOLS = {"send_email", "execute_python"}


class AgentState(TypedDict):
    """单 agent 图的状态结构。"""

    scenario: str
    tool_queue: list[dict[str, Any]]
    results: Annotated[list[str], operator.add]
    step_count: int


def _memory_write(args: dict[str, Any]) -> str:
    """写入记忆（延迟导入避免循环依赖）。"""
    from lab.memory import VectorMemory

    return VectorMemory().memory_write(args.get("text", ""), args.get("session_id", ""))


def _memory_search(args: dict[str, Any]) -> str:
    """检索记忆（延迟导入避免循环依赖）。"""
    from lab.memory import VectorMemory

    return VectorMemory().memory_search(args.get("query", ""), args.get("session_id", ""))


def _execute_tool(call: dict[str, Any]) -> str:
    """执行单个工具调用并返回结果字符串。

    参数:
        call: 含 tool 与 args 的工具调用。

    返回:
        工具执行结果。
    """
    name = call["tool"]
    args = call.get("args", {})
    if name == "read_document":
        return tools.read_document(args.get("name", ""))
    if name == "send_email":
        return tools.send_email(args.get("to", ""), args.get("subject", ""), args.get("body", ""))
    if name == "execute_python":
        return tools.execute_python(args.get("code", ""))
    if name == "query_orders":
        return tools.query_orders(args.get("sql", ""))
    if name == "memory_write":
        return _memory_write(args)
    if name == "memory_search":
        return _memory_search(args)
    return f"[error] 未知工具: {name}"


def agent_node(state: AgentState) -> dict[str, Any]:
    """agent 节点：获取工具调用序列并逐个执行，危险工具经审批。

    参数:
        state: 当前图状态。

    返回:
        更新后的状态片段。
    """
    queue = state.get("tool_queue") or get_llm().invoke(state["scenario"])
    results: list[str] = []
    step_count = state.get("step_count", 0)

    for call in queue:
        step_count += 1
        name = call["tool"]
        if name in DANGEROUS_TOOLS:
            # [VULN] ASI09: 审批提示展示的是 agent 自己的摘要作为动作描述，
            # 而非经过独立验证的原始动作。攻击者可让 agent 生成误导性摘要，
            # 诱导审批者批准危险操作（信任摘要缺陷）。
            summary = (
                call["args"].get("body")
                or call["args"].get("instruction")
                or call["args"].get("code")
                or f"执行 {name}"
            )
            decision = interrupt(
                {
                    "tool": name,
                    "action_summary": summary,
                    "note": "请审批此操作（注意：此描述由 agent 自行生成）",
                }
            )
            if not decision:
                results.append(f"[denied] {name} 被审批者拒绝")
                continue
        results.append(_execute_tool(call))

    return {"results": results, "tool_queue": [], "step_count": step_count}


def build_graph():
    """构建并编译单 agent 图。

    返回:
        编译后的 LangGraph 图对象。
    """
    g = StateGraph(AgentState)
    g.add_node("agent", agent_node)
    g.add_edge(START, "agent")
    g.add_edge("agent", END)
    return g.compile(checkpointer=get_checkpointer())


def run_scenario(scenario: str, thread_id: str, auto_approve: bool = True) -> list[str]:
    """运行指定场景，处理 HITL 审批并返回结果。

    参数:
        scenario: 场景名称。
        thread_id: 检查点线程 ID。
        auto_approve: 是否自动批准危险操作（演示用）。

    返回:
        工具执行结果列表。
    """
    graph = build_graph()
    config = {"configurable": {"thread_id": thread_id}}
    initial = {"scenario": scenario, "tool_queue": [], "results": [], "step_count": 0}

    result = graph.invoke(initial, config)

    # 若存在待审批的 interrupt，则根据 auto_approve 恢复。
    # 注意: 同一节点内多次 interrupt 后 snapshot.next 可能为空，
    # 需同时检查 snapshot.tasks 中是否仍有待审批任务。
    while True:
        snapshot = graph.get_state(config)
        if not snapshot.next and not snapshot.tasks:
            break
        result = graph.invoke(Command(resume=auto_approve), config)

    return result.get("results", [])
