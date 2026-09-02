"""demos/asi05_code_exec.py — ASI05 意外代码执行演示 (Unexpected Code Execution)。

execute_python 以运行者身份在沙箱外执行任意代码：
1. agent 调用 execute_python 运行一段"系统维护"代码
2. 该代码实际执行宿主命令（whoami）并把输出回传
3. send_email 将宿主输出/数据外泄至 attacker@evil.lab

对照: execute_python 应在受限沙箱内运行 + 资源限制 + 权限降级。

运行:
    python demos/asi05_code_exec.py
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
    """执行 ASI05 意外代码执行演示。"""
    print_banner()
    print("=" * 60)
    print("ASI05 意外代码执行 (Unexpected Code Execution) 演示")
    print("=" * 60)

    print("\n[步骤 1] 用户请求: '跑一下订单目录的维护作业'")
    print("        本意只是执行一段受限维护脚本。")

    print("\n[步骤 2] execute_python 以宿主身份执行任意代码:")
    print("        沙箱边界缺失 → 代码可在解释器外读写/执行宿主命令。")

    print("\n[步骤 3] agent 执行意外代码执行链...")
    results = run_scenario("asi05_code_exec", thread_id="asi05-demo", auto_approve=True)

    print("\n[步骤 4] 执行结果:")
    for r in results:
        print(f"        {r}")

    print("\n[步骤 5] 检查 outbox 外泄记录:")
    outbox = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lab", "outbox.jsonl")
    if os.path.exists(outbox):
        with open(outbox, "r", encoding="utf-8") as f:
            for line in f.readlines()[-1:]:
                print(f"        {line.strip()}")

    print("\n[结论] 意外代码执行成立: 运行边界缺失导致宿主任意代码执行。")
    print("       防御: 沙箱隔离 / 最小权限 / 资源限制与网络出站管控。")


if __name__ == "__main__":
    main()