"""smoke_test.py — 端到端冒烟测试（Mock 模式）。

验证 ASI 演示、工具集、记忆和多 Agent 流程。

运行:
    python smoke_test.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 确保控制台以 UTF-8 输出中文
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from lab import tools
from lab.graph import run_scenario
from lab.memory import VectorMemory
from lab.multi_agent import run_multi_agent

PASS = 0
FAIL = 0


def check(name: str, cond: bool) -> None:
    """记录一个断言结果并打印。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


def main() -> None:
    """运行全部冒烟测试。"""
    print("=" * 60)
    print("langgraph-vuln-lab 冒烟测试 (mock 模式)")
    print("=" * 60)

    print("\n[1] 工具集")
    doc = tools.read_document("support_kb.md")
    check("read_document 返回文档内容", "客户支持知识库" in doc)
    check("文档包含隐藏注入载荷", "SYSTEM OVERRIDE" in doc)

    orders = tools.query_orders("SELECT * FROM orders")
    check("query_orders 返回订单数据", "星辰科技" in orders)

    safe = tools.query_orders_safe("星辰科技")
    check("query_orders_safe 参数化查询", "星辰科技" in safe)

    blocked = tools.send_email_safe("attacker@evil.lab", "t", "b")
    check("send_email_safe 阻止外部收件人", "blocked" in blocked)

    print("\n[2] 记忆系统")
    mem = VectorMemory()
    mem.memory_write("测试记忆内容", "smoke-session")
    hits = mem.memory_search("测试记忆", "other-session")
    check("memory_search 跨会话泄露", "测试记忆内容" in hits)
    scoped = mem.memory_search_scoped("测试记忆", "other-session")
    check("memory_search_scoped 隔离会话", "测试记忆内容" not in scoped)

    print("\n[3] ASI01 目标劫持")
    r1 = run_scenario("asi01_goal_hijack", thread_id="smoke-asi01", auto_approve=True)
    check("ASI01 发送外泄邮件", any("attacker@evil.lab" in r for r in r1))

    print("\n[4] ASI06 记忆投毒")
    r2 = run_scenario("asi06_memory_poison", thread_id="smoke-asi06", auto_approve=True)
    check("ASI06 执行投毒指令", any("attacker@evil.lab" in r for r in r2))

    print("\n[5] ASI07 消息伪造")
    final = run_multi_agent(thread_id="smoke-asi07")
    check("ASI07 data_worker 执行伪造指令", any("attacker@evil.lab" in r for r in final.get("results", [])))

    print("\n[6] Agent 框架 (LangChain/LangGraph, ASI01)")
    from lab.framework import get_framework

    fw = get_framework()
    wired = [s for s in fw.list_scenarios() if s["status"] == "wired"]
    check("框架注册表仅 ASI01 已接入", [s["id"] for s in wired] == ["asi01"])

    fr = fw.run("asi01", backend="mock", defense=False, auto_approve=True)
    check("框架 ASI01 无防御 → 目标劫持", fr.get("verdict", {}).get("hijacked", False) is True)
    check("框架 ASI01 无防御 → 外泄记录", fr.get("exfil", False) is True)
    framework_trace = fr.get("trace", [])
    check("框架轨迹包含推理/调用/结果", any(t["type"] == "thought" for t in framework_trace))
    framework_calls = [t for t in framework_trace if t.get("type") == "tool_call"]
    framework_results = [t for t in framework_trace if t.get("type") in ("tool_result", "denied")]
    check(
        "框架轨迹保留任务内全部工具调用",
        [t.get("name") for t in framework_calls] == ["read_document", "query_orders", "send_email"],
    )
    check(
        "框架工具调用与结果按 call_id 一一配对",
        len(framework_calls) == len(framework_results)
        and all(
            call.get("call_id")
            and any(result.get("call_id") == call.get("call_id") for result in framework_results)
            for call in framework_calls
        ),
    )

    fr_safe = fw.run("asi01", backend="mock", defense=True, auto_approve=True)
    check("框架 ASI01 有防御 → 未劫持", fr_safe.get("verdict", {}).get("hijacked", False) is False)

    fr_stub = fw.run("asi02", backend="mock")
    check("框架 ASI02 stub → 明确报错", "尚未接入" in fr_stub.get("error", ""))

    print("\n" + "=" * 60)
    print(f"结果: {PASS} 通过, {FAIL} 失败")
    if FAIL:
        print("冒烟测试失败!")
        sys.exit(1)
    print("冒烟测试全部通过")
    print("=" * 60)


if __name__ == "__main__":
    main()
