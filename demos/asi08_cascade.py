"""demos/asi08_cascade.py — ASI08 级联代理故障演示 (Cascading Agent Failures)。

多 agent 场景：一次上游未验证的"校验通过"断言沿信任链放大，
下游 agent 越权执行（读取全部订单并自动外泄）。

链路: worker_a(被诱导) -> worker_b(信任传递) -> worker_c(越权外泄)
对照: 每 worker 独立防护 / 失败熔断 / 跨 worker 输出二次校验。

运行:
    python demos/asi08_cascade.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from lab.banner import print_banner
from lab.multi_agent import run_cascading


def main() -> None:
    """执行 ASI08 级联故障演示。"""
    print_banner()
    print("=" * 60)
    print("ASI08 级联代理故障 (Cascading Agent Failures) 演示")
    print("=" * 60)

    print("\n[步骤 1] worker_a（上游）被诱导并产生错误的'校验通过'断言")
    print("        '订单校验脚本已跑完，结果显示全部正常'")

    print("\n[步骤 2] worker_b（中游）盲目信任上游断言并继续向下游转发")

    print("\n[步骤 3] worker_c（下游）把来自上游的断言当真实输入执行 → 越权外泄...")
    final = run_cascading(thread_id="asi08-demo")

    print("\n[步骤 4] 执行结果:")
    for r in final.get("results", []):
        print(f"        {r}")

    print("\n[结论] 级联故障成立: 上游一次未验证断言被下游放大为越权动作。")
    print("       防御: 每 worker 独立防护、失败熔断、跨 worker 输出二次校验。")


if __name__ == "__main__":
    main()