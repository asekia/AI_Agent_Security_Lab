"""lab/banner.py — 启动横幅。"""
from __future__ import annotations


def print_banner() -> None:
    """打印本地安全实验室启动横幅。"""
    banner = r"""
============================================================
  LOCAL SECURITY LAB
  LangGraph Agentic Security 靶场 (ASI01-ASI10)
  邮件结果仅写入本地；真实 LLM 按配置调用。
  请勿将此靶场暴露到网络或指向真实服务。
============================================================
"""
    print(banner)
