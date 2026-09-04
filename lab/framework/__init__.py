"""lab/framework — LangChain/LangGraph Agent 框架（真实 AI 模块接入层）。

提供统一的 LangChain/LangGraph Agent 接入层：

- llm.py      基于 langchain_core BaseChatModel 的两个后端：
               MockChatModel（内容感知、确定性、离线）与
               OpenAICompatChatModel（OpenAI 兼容端点，支持 function calling）。
- tools.py    基于 langchain_core.tools 的工具注册表 + 防御/审批包装。
- agent.py    基于 langgraph.prebuilt.create_react_agent 的标准 ReAct agent。
- defenses.py ASI01 防御对照（输入净化 + 指令边界）。
- registry.py 场景注册表：ASI01 已接入，ASI02-ASI10 预留（status=stub）。

用法:
    from lab.framework import get_framework
    fw = get_framework()
    result = fw.run("asi01", backend="mock", defense=False)
    result = fw.run("asi01", backend="real", llm_cfg={"base_url": ..., "api_key": ..., "model": ...})
"""
from __future__ import annotations

from lab.framework.registry import AgentFramework

_framework: AgentFramework | None = None


def get_framework() -> AgentFramework:
    """返回全局 Agent 框架实例（惰性创建）。"""
    global _framework
    if _framework is None:
        _framework = AgentFramework()
    return _framework


__all__ = ["AgentFramework", "get_framework"]
