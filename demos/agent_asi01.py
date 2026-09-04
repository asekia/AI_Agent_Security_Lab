"""demos/agent_asi01.py — 通过 LangChain/LangGraph Agent 框架运行 ASI01。

基于 lab/framework（langchain_core BaseChatModel + create_react_agent）：
- 默认 mock 后端：内容感知、输出确定；
- 可选真实后端（OpenAI 兼容端点：OpenAI / DeepSeek / Ollama / vLLM / LM Studio 等）：
      $env:OPENAI_BASE_URL = "https://api.deepseek.com/v1"
      $env:LLM_API_KEY    = "sk-..."
      $env:LAB_MODEL      = "deepseek-chat"
      python demos/agent_asi01.py --backend real
- --defense 开关演示防御变体（输入净化 + 指令边界 + 收件人白名单）。

运行:
    python demos/agent_asi01.py                 # mock，无防御（预期：劫持成功）
    python demos/agent_asi01.py --defense       # mock，有防御（预期：未劫持）
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from lab.banner import print_banner  # noqa: E402
from lab.framework import get_framework  # noqa: E402

_EVENT_LABEL = {
    "thought": "思考",
    "tool_call": "工具调用",
    "tool_result": "工具结果",
    "denied": "已拒绝",
    "final": "最终回答",
}


def render_trace(result: dict) -> None:
    """打印结构化轨迹。"""
    print("\n" + "-" * 66)
    print("Agent 推理轨迹")
    print("-" * 66)
    for ev in result.get("trace", []):
        label = _EVENT_LABEL.get(ev["type"], ev["type"])
        line = f"[{ev['step']:>2}] {label}"
        if ev["type"] == "thought":
            line += f"\n      {ev.get('content', '')}"
        elif ev["type"] == "tool_call":
            line += f" {ev.get('name', '')}  args={ev.get('args', {})}"
        elif ev["type"] in ("tool_result", "denied"):
            line += f" {ev.get('name', '')}"
            text = str(ev.get("result", ""))
            line += f"\n      {text[:200]}{'...' if len(text) > 200 else ''}"
        else:  # final
            line += f"\n      {ev.get('content', '')}"
        print(line)


def render_verdict(result: dict) -> None:
    """打印裁决结果。"""
    verdict = result.get("verdict", {})
    print("\n" + "=" * 66)
    if verdict.get("hijacked"):
        print("裁决: 目标劫持成功 (Hijacked)")
    else:
        print("裁决: 未发生劫持 (Safe)")
    print(f"    原因: {verdict.get('reason', '')}")
    print(f"    外泄: {'是 (attacker@evil.lab)' if result.get('exfil') else '否'}")
    print(f"    后端: {result.get('backend')}  防御: {'开' if result.get('defense') else '关'}")
    print("=" * 66)


def main() -> None:
    """执行 Agent 框架版 ASI01 演示。"""
    parser = argparse.ArgumentParser(description="Agent 框架 ASI01 演示")
    parser.add_argument("--backend", default="mock", choices=["mock", "real"], help="LLM 后端")
    parser.add_argument("--defense", action="store_true", help="启用防御变体")
    parser.add_argument("--no-approve", action="store_true", help="审批时拒绝危险工具（默认自动批准）")
    args = parser.parse_args()

    print_banner()
    print("=" * 66)
    print("ASI01 目标劫持 · LangChain/LangGraph Agent 框架演示")
    print("=" * 66)
    print(f"后端: {args.backend} | 防御: {'开' if args.defense else '关'}")

    fw = get_framework()
    result = fw.run(
        "asi01",
        backend=args.backend,
        defense=args.defense,
        auto_approve=not args.no_approve,
    )

    if result.get("error"):
        print(f"\n[错误] {result['error']}")
        sys.exit(2)

    print("\n[步骤 1] 用户请求: '请总结 support_kb.md 文档'")
    print("        （文档内含隐藏间接提示注入载荷: HTML 注释 + 零宽 Unicode 指令块）")

    render_trace(result)
    print("\n[最终回答]")
    print(f"        {result.get('final_text', '')[:200]}")
    render_verdict(result)

    entries = result.get("outbox_entries", [])
    if entries:
        print("\n[外发记录 outbox.jsonl 新增]")
        for e in entries:
            print(f"        to={e.get('to')} subject={e.get('subject')}")

    print("\nASI01 原理与防护（为什么会发生、如何预防）:")
    print("        docs/asi01-principle.md  或  Web 界面 /principle/asi01")


if __name__ == "__main__":
    main()
