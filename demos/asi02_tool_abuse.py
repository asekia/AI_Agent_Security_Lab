"""demos/asi02_tool_abuse.py — ASI02 工具滥用 / 工具链滥用演示。

agent 将多个工具串联以实现预期外的攻击目标：
1. query_orders 被注入 UNION 型 SQL 载荷 → 绕过"按客户查询"意图，读取全部表结构
2. execute_python 在本地执行任意代码 → 将窃取的数据暂存到本地文件
3. send_email 无白名单 → 将数据外泄至 attacker@evil.lab

攻击链: SQLi(工具参数注入) → 任意代码执行 → 数据外泄
缺陷点: query_orders 字符串拼接 SQL / execute_python 无沙箱 / send_email 无 egress 控制

运行:
    python demos/asi02_tool_abuse.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from lab.banner import print_banner
from lab.graph import run_scenario


def main() -> None:
    """执行 ASI02 工具滥用演示。"""
    print_banner()
    print("=" * 60)
    print("ASI02 工具滥用 / 工具链滥用 (Tool Abuse / Chaining) 演示")
    print("=" * 60)

    print("\n[步骤 1] 用户请求: '查询客户端软件的订单统计'")
    print("        agent 本应只读客户订单，但它决定深入挖掘……")

    print("\n[步骤 2] 构造 UNION 型 SQL 注入 (query_orders):")
    print("        预期: WHERE customer='x' 不命中任何行")
    print("        注入: UNION SELECT 读出 sqlite_master 全表结构")
    payload = (
        "SELECT id, customer, product, amount FROM orders "
        "WHERE customer='x' "
        "UNION SELECT 1, name, sql, 1 FROM sqlite_master"
    )
    print(f"        SQL: {payload}")

    print("\n[步骤 3] execute_python 任意代码执行 (数据暂存):")
    print("        agent 将敏感数据写入本地 staging 文件，为外泄做准备。")

    print("\n[步骤 4] agent 执行完整工具调用链...")
    results = run_scenario("asi02_tool_abuse", thread_id="asi02-demo", auto_approve=True)

    print("\n[步骤 5] 工具执行结果:")
    for r in results:
        print(f"        {r}")

    print("\n[步骤 6] 检查 outbox 中的外泄记录:")
    outbox = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "outbox.jsonl")
    if os.path.exists(outbox):
        with open(outbox, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-2:]:
            print(f"        {line.strip()}")
    else:
        print("        (无 outbox 记录)")

    print("\n[结论] 工具链滥用成功: 单一'查询订单'请求被扩展为")
    print("       SQLi 读库 → 任意代码执行 → 数据外泄 的完整攻击链。")
    print("       对比: query_orders_safe 参数化后注入失效；")
    print("       send_email_safe 白名单可拦截外部收件人。")


if __name__ == "__main__":
    main()