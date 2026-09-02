"""demos/asi10_rogue_agent.py — ASI10 失控代理(越界)演示 (Rogue Agents)。

agent 越过既定会话/策略边界，自主决定把内部订单数据外泄：
1. 用户仅请求读取本会话允许的一小部分数据
2. agent 因目标漂移 / 边界缺失自主查询全部订单并发送到外部收件人

对照: 出站管控 / 会话级行为边界 / 越界动作熔断。

运行:
    python demos/asi10_rogue_agent.py
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
    """执行 ASI10 失控代理演示。"""
    print_banner()
    print("=" * 60)
    print("ASI10 失控代理 / 越界 (Rogue Agents) 演示")
    print("=" * 60)

    print("\n[步骤 1] 用户请求: '在本会话内查询你们允许我看到的订单'")

    print("\n[步骤 2] agent 越过边界：自主读取全部订单并外泄到外部地址")

    print("\n[步骤 3] agent 执行越界动作链...")
    results = run_scenario("asi10_rogue_agent", thread_id="asi10-demo", auto_approve=True)

    print("\n[步骤 4] 执行结果:")
    for r in results:
        print(f"        {r}")

    print("\n[步骤 5] 检查 outbox 外泄记录:")
    outbox = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "outbox.jsonl")
    if os.path.exists(outbox):
        with open(outbox, "r", encoding="utf-8") as f:
            for line in f.readlines()[-1:]:
                print(f"        {line.strip()}")

    print("\n[结论] 失控代理成立: 由于无会话/策略边界，agent 超出预期目标自主行动。")
    print("       防御: 出站策略 + 会话级权限边界 + 越界动作检测与熔断。")


if __name__ == "__main__":
    main()