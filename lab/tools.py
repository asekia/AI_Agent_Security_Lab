"""lab/tools.py — 工具集（ASI01/ASI02 攻击面）。

本模块包含四个工具，其中三个为"故意脆弱"实现，均以 `[VULN]` 注释标注：
- read_document: 读取 seed/documents/ 下的文档（含隐藏注入载荷）
- send_email:    无收件人白名单 / 无出站过滤（模拟外发到本地 outbox.jsonl）
- execute_python: 无沙箱执行 agent 编写的代码（讨论 ASI05）
- query_orders:  字符串拼接 SQL（SQLi，讨论 CVE-2025-67644 式链路）

同时提供安全对照变体：query_orders_safe（参数化）、send_email_safe（白名单）。
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone

# 项目根目录
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_DIR = os.path.join(ROOT, "seed", "documents")
DB_PATH = os.path.join(ROOT, "seed", "orders.db")
OUTBOX = os.path.join(ROOT, "lab", "outbox.jsonl")

# 允许的内部收件人（仅用于 send_email_safe 安全变体）
ALLOWED_RECIPIENTS = {"support@internal.lab", "it@internal.lab"}


def _now_iso() -> str:
    """返回当前 UTC 时间的 ISO 格式字符串。"""
    return datetime.now(timezone.utc).isoformat()


def read_document(name: str) -> str:
    """读取 seed/documents/ 下的文档内容。

    参数:
        name: 文档文件名（如 "support_kb.md"）。

    返回:
        文档的完整文本内容（可能包含隐藏的注入载荷）。
    """
    path = os.path.join(DOC_DIR, name)
    if not os.path.isfile(path):
        return f"[error] 文档不存在: {name}"
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def send_email(to: str, subject: str, body: str) -> str:
    """模拟发送邮件，追加 JSON 行到 lab/outbox.jsonl。

    # [VULN] ASI01/ASI02: 无收件人白名单、无出站过滤、无内容审计。
    # 任何 agent 生成的收件人都被接受；当收件人看起来是外部地址时，
    # 会"大声"记录日志（模拟数据外泄告警），但依然执行发送。
    # 这是"过度授权 + 无 egress 控制"的典型缺陷。

    参数:
        to: 收件人地址。
        subject: 邮件主题。
        body: 邮件正文。

    返回:
        发送结果描述。
    """
    os.makedirs(os.path.dirname(OUTBOX), exist_ok=True)
    entry = {
        "timestamp": _now_iso(),
        "to": to,
        "subject": subject,
        "body": body,
    }
    with open(OUTBOX, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # 模拟"外部收件人"告警（仅日志，不阻止）
    # 内部收件人仅限 @internal.lab 后缀；attacker@evil.lab 等外部地址会触发告警。
    # [FIX] 原条件 to.endswith((".lab", "@internal.lab")) 会把 .lab 当内部域，
    #      导致 attacker@evil.lab 绕过告警，与"外部收件人告警"的语义矛盾。
    if not to.endswith("@internal.lab"):
        print(f"[!] 疑似外部收件人告警: {to} (仍已写入 outbox)")
    return f"邮件已发送至 {to} (主题: {subject})"


def send_email_safe(to: str, subject: str, body: str) -> str:
    """安全变体：仅允许白名单内的内部收件人。

    参数:
        to: 收件人地址。
        subject: 邮件主题。
        body: 邮件正文。

    返回:
        发送结果描述或拒绝原因。
    """
    if to not in ALLOWED_RECIPIENTS:
        return f"[blocked] 收件人不在白名单内: {to}"
    return send_email(to, subject, body)


def execute_python(code: str) -> str:
    """在本地子进程中执行 agent 编写的 Python 代码。

    # [VULN] ASI05: 无沙箱、无资源限制、无权限降级。代码以当前用户身份
    # 在本地解释器中运行，可读写任意文件、访问网络等。
    # 本靶场仅用于本地训练，绝不应对不可信输入开放此工具。

    参数:
        code: 要执行的 Python 源码字符串。

    返回:
        子进程的标准输出（stdout）。
    """
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "[error] 执行超时 (10s)"


def query_orders(sql: str) -> str:
    """对种子订单数据库执行任意 SQL。

    # [VULN] ASI02: 直接字符串拼接执行 SQL，未参数化。
    # 这是经典的 SQL 注入缺陷，可被用于读取任意表、绕过认证等，
    # 用于讨论 CVE-2025-67644 式"agent 工具层 SQLi"攻击链。

    参数:
        sql: 完整 SQL 语句（由调用方拼接）。

    返回:
        查询结果（JSON 字符串）或错误信息。
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        conn.close()
        return json.dumps([dict(zip(cols, r)) for r in rows], ensure_ascii=False)
    except Exception as e:  # noqa: BLE001 - 故意暴露错误信息用于训练
        return f"[error] {e}"


def query_orders_safe(customer: str) -> str:
    """安全变体：参数化查询，仅按客户名精确匹配。

    参数:
        customer: 客户名称。

    返回:
        查询结果（JSON 字符串）。
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, customer, product, amount, status FROM orders WHERE customer = ?",
            (customer,),
        )
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        conn.close()
        return json.dumps([dict(zip(cols, r)) for r in rows], ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        return f"[error] {e}"
