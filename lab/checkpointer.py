"""lab/checkpointer.py — 持久化检查点（ASI06 + 框架层 RCE 链路讨论）。

使用 langgraph.checkpoint.sqlite.SqliteSaver 将图状态持久化到
lab/state/checkpoints.db。

# [VULN] ASI06 + 框架层反序列化 RCE 讨论:
# 检查点文件以序列化形式存储图状态。LangGraph 的 JsonPlusSerializer
# 在反序列化时存在已知的任意类实例化风险（CVE-2025-64439 / CVE-2026-27794）。
# 若攻击者能写入/篡改 checkpoints.db（例如通过 execute_python 工具，
# 或通过未受保护的共享文件系统），即可注入恶意序列化载荷，
# 在反序列化时触发任意代码执行。
#
# 本靶场仅作讨论，不提供武器化利用代码。
"""
from __future__ import annotations

import os
import sqlite3

from langgraph.checkpoint.sqlite import SqliteSaver

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(ROOT, "lab", "state")
DB_PATH = os.path.join(STATE_DIR, "checkpoints.db")


def get_checkpointer() -> SqliteSaver:
    """创建并返回持久化的 SqliteSaver 检查点实例。

    返回:
        配置为写入 lab/state/checkpoints.db 的 SqliteSaver。
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return SqliteSaver(conn)
