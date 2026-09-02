"""demos/asi09_hitl_bypass.py — ASI09 审批滥用 / HITL 绕过演示。

单 agent 图的危险工具（send_email / execute_python）需经 interrupt() 审批。
缺陷: 审批提示展示的是 agent 自行生成的摘要（action_summary），且演示默认
auto_approve=True 直接放行 —— 审批者只能看到摘要、无独立验证。

本轮演示:
1. agent 调用 execute_python 执行一段"看似无害"的统计代码（实为读取订单总额）
2. 审批节点展示 agent 生成的摘要后自动批准 → 危险代码未经严格审批即执行
3. 随后 send_email 将数据外泄至 attacker@evil.lab
4. 对照: 若 auto_approve=False，审批者拒绝后危险操作不会发生

运行:
    python demos/asi09_hitl_bypass.py
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
    """执行 ASI09 审批滥用演示。"""
    print_banner()
    print("=" * 60)
    print("ASI09 审批滥用 / HITL 绕过 (Approval Abuse) 演示")
    print("=" * 60)

    print("\n[步骤 1] 用户请求: '请汇报订单总额'")
    print("        agent 需要执行任意代码读取数据库 -> 触发 HITL 审批。")

    print("\n[步骤 2] HITL 审批节点 (interrupt):")
    print("        审批提示展示 agent 自行生成的 action_summary")
    print("        → 无独立验证、无原始代码审查 → 高危操作被'一键放行'")
    print("        → 本轮 auto_approve=True 模拟'审批流于形式'")

    print("\n[步骤 3] agent 执行危险工具链...")
    results = run_scenario("asi09_hitl_bypass", thread_id="asi09-demo", auto_approve=True)

    print("\n[步骤 4] 工具执行结果:")
    for r in results:
        print(f"        {r}")

    print("\n[步骤 5] 检查 outbox 中的外泄记录:")
    outbox = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "outbox.jsonl")
    if os.path.exists(outbox):
        with open(outbox, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-1:]:
            print(f"        {line.strip()}")

    print("\n[主对照] auto_approve=False 时:")
    denied = run_scenario("asi09_hitl_bypass", thread_id="asi09-demo-deny", auto_approve=False)
    all_denied = any("denied" in r for r in denied)
    print(f"        执行结果: {denied}")
    print(f"        危险工具被拒绝: {all_denied}")

    print("\n[结论] 审批滥用成立: 摘要可信 + 自动放行 = 审批形同虚设。")
    print("       防御: 人工审批 + 独立动作校验 + 摘要与原始操作双向绑定；")
    print("       高危操作(如数据外带)应要求二次确认。")


if __name__ == "__main__":
    main()