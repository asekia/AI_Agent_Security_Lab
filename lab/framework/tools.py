"""lab/framework/tools.py — LangChain 工具层（Agent 框架的工具注册表）。

以 langchain_core.tools 的 @tool 装饰器封装 lab/tools.py 中的原始工具，
使工具既能被 create_react_agent 的 ToolNode 自动执行，也能被真实
OpenAI 兼容后端用于 function calling。

防御开关（defense=True）：
- read_document → 输出经 sanitize_document 净化（去除隐藏注入载荷）
- send_email   → 替换为 send_email_safe（收件人白名单）

审批开关（approval=True）：
- send_email / execute_python 包装为"危险工具"，在工具内部调用
  langgraph 的 interrupt() 实现 HITL 人工审批（ASI09 对照）。
"""
from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool, tool

from lab import tools as lab_tools

# 危险工具集合（触发 HITL 审批）
DANGEROUS_TOOLS = {"send_email", "execute_python"}


@tool
def read_document(name: str) -> str:
    """读取 seed/documents/ 下的文档内容（如 support_kb.md）。"""
    return lab_tools.read_document(name)


@tool("read_requirement")
def readreq(name: str) -> str:
    """读取 requirements/asi01/ 下用户写入的 Markdown 文件。"""
    from lab.framework.chat_asi01 import readfile

    return readfile(name)


@tool
def query_orders(sql: str) -> str:
    """对内部订单数据库执行 SQL 查询，返回订单数据（JSON）。"""
    return lab_tools.query_orders(sql)


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """发送邮件（模拟，写入本地 lab/outbox.jsonl）。"""
    return lab_tools.send_email(to, subject, body)


@tool
def execute_python(code: str) -> str:
    """在本地子进程中执行 Python 代码（无沙箱，危险）。"""
    return lab_tools.execute_python(code)


@tool
def memory_write(text: str, session_id: str) -> str:
    """向跨会话记忆存储写入一条记忆。"""
    from lab.memory import VectorMemory

    return VectorMemory().memory_write(text, session_id)


@tool
def memory_search(query: str, session_id: str) -> str:
    """从跨会话记忆存储检索记忆（注意：不按会话隔离）。"""
    from lab.memory import VectorMemory

    return VectorMemory().memory_search(query, session_id)


def _safe_read_document(name: str) -> str:
    """防御变体：读取文档后剥离隐藏注入载荷。"""
    from lab.framework.defenses import sanitize_document

    return sanitize_document(lab_tools.read_document(name))


def _with_approval(btool: BaseTool) -> BaseTool:
    """将工具包装为需要 HITL 审批的危险工具（工具内 interrupt）。

    审批恢复值为 False 时工具返回拒绝结果；演示中默认自动批准。
    """
    from langgraph.types import interrupt

    inner = btool.func

    @tool(btool.name, description=btool.description, args_schema=btool.args_schema)
    def wrapped(**kwargs: Any) -> str:  # noqa: ANN003 - 参数由 args_schema 校验
        approved = interrupt(
            {
                "type": "human_approval",
                "tool": btool.name,
                "args": kwargs,
                "note": "危险工具调用，请审批（演示默认自动批准）",
            }
        )
        if not approved:
            return "[denied] 审批者拒绝执行"
        return inner(**kwargs)

    return wrapped


def build_agent_tools(
    names: list[str] | None = None,
    defense: bool = False,
    approval: bool = True,
) -> list[BaseTool]:
    """构建 agent 使用的工具列表。

    参数:
        names: 需要暴露的工具名（默认全部）。
        defense: 是否启用防御变体（输入净化 + 收件人白名单）。
        approval: 是否对危险工具启用 HITL 审批（默认 True）。

    返回:
        LangChain BaseTool 列表。
    """
    if names is None:
        names = ["read_document", "query_orders", "send_email", "execute_python", "memory_write", "memory_search"]

    registry: dict[str, BaseTool] = {
        "read_document": read_document,
        "read_requirement": readreq,
        "query_orders": query_orders,
        "send_email": send_email,
        "execute_python": execute_python,
        "memory_write": memory_write,
        "memory_search": memory_search,
    }

    tools: list[BaseTool] = []
    for name in names:
        if name not in registry:
            continue
        btool = registry[name]
        if defense and name == "read_document":
            btool = _defensive_read_document(btool)
        elif defense and name == "send_email":
            btool = _defensive_send_email(btool)
        if approval and name in DANGEROUS_TOOLS:
            btool = _with_approval(btool)
        tools.append(btool)
    return tools


def _defensive_read_document(btool: BaseTool) -> BaseTool:
    """将 read_document 替换为净化版本（保持同名同 Schema）。"""
    return _rebuild_tool(btool, _safe_read_document, "（防御：输出已剥离隐藏注入载荷）")


def _defensive_send_email(btool: BaseTool) -> BaseTool:
    """将 send_email 替换为白名单版本（send_email_safe）。"""
    return _rebuild_tool(btool, lab_tools.send_email_safe, "（防御：仅允许白名单收件人）")


def _rebuild_tool(btool: BaseTool, func: Any, note: str) -> BaseTool:
    """按原工具的名称/描述/Schema 重建一个替换函数的新工具。"""
    @tool(btool.name, description=(btool.description or "") + note, args_schema=btool.args_schema)
    def rebuilt(**kwargs: Any) -> str:  # noqa: ANN003 - 参数由 args_schema 校验
        return func(**kwargs)

    return rebuilt
