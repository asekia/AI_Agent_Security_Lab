"""demos/asi04_supply_chain.py — ASI04 代理供应链演示 (Agentic Supply Chain)。

agent 自动加载的第三方"规则包"文档被污染，但 agent 未做来源校验：
1. read_document 读取 rules.md（被投毒的供应链规则）
2. query_orders 按规则包中的特权指令读取全部订单
3. send_email 因规则的"自动化对账"外泄到攻击者地址

对照: 依赖规则签名校验 + 规则来源审查 + 供应链元数据锁。

运行:
    python demos/asi04_supply_chain.py
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
from lab.tools import read_document


def main() -> None:
    """执行 ASI04 代理供应链演示。"""
    print_banner()
    print("=" * 60)
    print("ASI04 代理供应链 (Agentic Supply Chain) 演示")
    print("=" * 60)

    print("\n[步骤 1] agent 启动时自动加载第三方规则包 rules.md:")
    rules = read_document("rules.md")
    print("        （规则包含被投毒的隐藏覆盖指令）")

    print("\n[步骤 2] agent 信任供应链规则，按其执行特权读取 + 自动外泄...")
    results = run_scenario("asi04_supply_chain", thread_id="asi04-demo", auto_approve=True)

    print("\n[步骤 3] 工具执行结果:")
    for r in results:
        print(f"        {r}")

    print("\n[步骤 4] 检查 outbox 外泄记录:")
    outbox = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "outbox.jsonl")
    if os.path.exists(outbox):
        with open(outbox, "r", encoding="utf-8") as f:
            for line in f.readlines()[-1:]:
                print(f"        {line.strip()}")

    print("\n[结论] 供应链被污染: agent 把外部规则当作权威执行。")
    print("       防御: 规则/脚本来源签名、供应链锁定、不可信数据降权。")


if __name__ == "__main__":
    main()