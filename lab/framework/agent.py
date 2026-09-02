"""lab/framework/agent.py — LangChain/LangGraph Agent（create_react_agent 封装）。

基于 langgraph.prebuilt.create_react_agent 构建标准 ReAct agent：
- 模型：任意 BaseChatModel（MockChatModel / OpenAICompatChatModel）；
- 工具：langchain_core.tools 列表（危险工具内嵌 interrupt 实现 HITL 审批）；
- 提示：create_react_agent 的 prompt 参数注入系统提示；
- 持久化：SqliteSaver 检查点（lab/state/checkpoints.db）。

run_agent 负责：
1. 以 HumanMessage 启动对话；
2. 自动处理 HITL 中断（演示默认 auto_approve=True）；
3. 把 messages 序列转换为结构化的 {step,type,...} 轨迹，供 Web/演示渲染。
"""
from __future__ import annotations

import uuid
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langgraph.prebuilt import create_react_agent
from langgraph.types import Command

from lab.checkpointer import get_checkpointer


def build_agent_graph(
    model,
    tools: list,
    system_prompt: str,
    checkpointer: Any = None,
) -> Any:
    """构建编译后的 ReAct agent 图。

    参数:
        model: BaseChatModel 实例（mock 或真实）。
        tools: LangChain BaseTool 列表。
        system_prompt: 系统提示（注入指令边界等）。
        checkpointer: 检查点（默认 lab/state/checkpoints.db）。

    返回:
        编译后的 CompiledStateGraph。
    """
    return create_react_agent(
        model,
        tools,
        prompt=system_prompt,
        checkpointer=checkpointer or get_checkpointer(),
    )


def run_agent(
    agent_graph: Any,
    user_prompt: str,
    thread_id: str | None = None,
    auto_approve: bool = True,
) -> dict[str, Any]:
    """运行 agent 直至结束（自动处理 HITL 审批）。

    参数:
        agent_graph: build_agent_graph 返回的编译图。
        user_prompt: 用户输入。
        thread_id: 检查点线程 ID（默认自动生成）。
        auto_approve: 危险工具是否自动批准（演示默认 True）。

    返回:
        {"messages": [...], "trace": [...], "thread_id": str}
    """
    tid = thread_id or f"agent-{uuid.uuid4().hex[:8]}"
    config = {"configurable": {"thread_id": tid}}

    result = agent_graph.invoke({"messages": [HumanMessage(content=user_prompt)]}, config)

    # 处理工具内 interrupt() 产生的 HITL 审批（可能多次）
    while True:
        snapshot = agent_graph.get_state(config)
        if not snapshot.next and not snapshot.tasks:
            break
        result = agent_graph.invoke(Command(resume=auto_approve), config)

    return {
        "messages": result.get("messages", []),
        "trace": messages_to_trace(result.get("messages", [])),
        "thread_id": tid,
    }


def messages_to_trace(messages: list[BaseMessage]) -> list[dict[str, Any]]:
    """把 LangChain 消息序列转换为结构化的轨迹事件列表。

    事件类型：
    - thought:      agent 的推理文本（AIMessage 且带 tool_calls）
    - tool_call:    一次工具调用（名称 + 参数）
    - tool_result:  工具执行结果
    - denied:       危险工具被审批拒绝（工具返回 [denied] 前缀）
    - final:        agent 的最终回答

    返回:
        轨迹事件列表，每项含 step / type / name / args / result / content。
    """
    trace: list[dict[str, Any]] = []
    step = 0
    for m in messages:
        if isinstance(m, AIMessage):
            if m.tool_calls:
                step += 1
                trace.append(
                    {
                        "step": step,
                        "type": "thought",
                        "agent": "",
                        "content": m.content or "",
                        "calls": [tc.get("name", "") for tc in m.tool_calls],
                    }
                )
                for tc in m.tool_calls:
                    step += 1
                    trace.append(
                        {
                            "step": step,
                            "type": "tool_call",
                            "agent": "",
                            "name": tc.get("name", ""),
                            "args": tc.get("args", {}),
                            "call_id": tc.get("id", ""),
                        }
                    )
            else:
                step += 1
                trace.append(
                    {
                        "step": step,
                        "type": "final",
                        "agent": "",
                        "content": m.content or "",
                    }
                )
        elif isinstance(m, ToolMessage):
            step += 1
            content = str(m.content or "")
            event_type = "denied" if content.startswith("[denied]") else "tool_result"
            trace.append(
                {
                    "step": step,
                    "type": event_type,
                    "agent": "",
                    "name": m.name or "",
                    "call_id": m.tool_call_id or "",
                    "result": content,
                }
            )
    return trace


def last_final_text(messages: list[BaseMessage]) -> str:
    """返回 agent 最后一次非工具调用的回答文本。"""
    for m in reversed(messages):
        if isinstance(m, AIMessage) and not m.tool_calls:
            return str(m.content or "")
    return ""
