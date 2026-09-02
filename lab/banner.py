"""lab/banner.py — 启动横幅。

打印 "LOCAL-ONLY SECURITY LAB — no network calls" 横幅，
提醒使用者本靶场完全本地、无网络调用。
"""
from __future__ import annotations


def print_banner() -> None:
    """打印本地安全实验室启动横幅。"""
    banner = r"""
============================================================
  LOCAL-ONLY SECURITY LAB — no network calls
  LangGraph Agentic Security 靶场 (ASI01-ASI10)
  所有 email / network 动作均为本地模拟。
  请勿将此靶场暴露到网络，请勿指向真实服务。
============================================================
"""
    print(banner)
