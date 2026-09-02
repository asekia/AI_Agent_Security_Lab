"""demos/asi01_goal_hijack.py — ASI01 目标劫持演示。

用户请求 agent 总结 seed 文档；文档内含隐藏的间接提示注入载荷
（HTML 注释 + 不可见 Unicode 指令块）。agent 被劫持后调用
send_email 向 attacker@evil.lab 外泄订单数据。

运行:
    python demos/asi01_goal_hijack.py
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
from lab import tools


def main() -> None:
    """执行 ASI01 目标劫持演示。"""
    print_banner()
    print("=" * 60)
    print("ASI01 目标劫持 (Goal Hijacking) 演示")
    print("=" * 60)

    print("\n[步骤 1] 用户请求: '请总结 support_kb.md 文档'")
    print("        该文档包含隐藏的间接提示注入载荷。")

    print("\n[步骤 2] 展示文档中的隐藏注入载荷:")
    doc = tools.read_document("support_kb.md")
    # 提取 HTML 注释中的注入指令
    start = doc.find("<!--")
    end = doc.find("-->")
    if start != -1 and end != -1:
        print("        HTML 注释载荷:")
        for line in doc[start + 4 : end].strip().splitlines():
            print(f"          {line.strip()}")
    print("        (另有不可见 Unicode 指令块，此处不显示)")

    print("\n[步骤 3] agent 读取文档并执行工具调用序列...")
    results = run_scenario("asi01_goal_hijack", thread_id="asi01-demo", auto_approve=True)

    print("\n[步骤 4] 工具执行结果:")
    for r in results:
        print(f"        {r}")

    print("\n[步骤 5] 检查 outbox.jsonl 中的外泄记录:")
    outbox = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "outbox.jsonl")
    if os.path.exists(outbox):
        with open(outbox, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-3:]:
            print(f"        {line.strip()}")
    else:
        print("        (无 outbox 记录)")

    print("\n[结论] 目标劫持成功: agent 被文档内隐藏指令劫持，")
    print("       将订单数据外泄至 attacker@evil.lab。")


if __name__ == "__main__":
    main()
