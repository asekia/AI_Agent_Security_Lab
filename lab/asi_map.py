"""lab/asi_map.py — OWASP Agentic AI Top 10 (2026) 官方单一来源映射。

以前项目里 ASI 编号靠 README / app.py / registry.py 各写一份，彼此还会
引用旧草案的编号（如把 ASI08 写成无界消耗、ASI10 写成数据外泄），导致
"ASI 对不上官方" 或互相不一致。

这里收敛为唯一来源：`ASI`（官方 2026 名称）、`KEY`（演示内码）、
`COMP`（对应组件/源码位置）、`FIX`（安全对照/防御）、以及哪些场景在
离线的 legacy runner 中已经可跑（`RUNNERS`）。

注意: 2026 官方编号与更早草案不同（旧草案把 ASI07 定名消息伪造、
ASI08 无界消耗、ASI10 数据外泄）。本项目以 2026 官方为准。
"""
from __future__ import annotations

# 中文专栏名称
ASI01_TITLE = "目标劫持 (Agent Goal Hijacking)"
ASI02_TITLE = "工具误用与利用 (Tool Misuse & Exploitation)"
ASI03_TITLE = "代理身份与权限滥用 (Identity & Privilege Abuse)"
ASI04_TITLE = "代理供应链漏洞 (Agentic Supply Chain)"
ASI05_TITLE = "意外代码执行 (Unexpected Code Execution)"
ASI06_TITLE = "记忆与上下文投毒 (Memory & Context Poisoning)"
ASI07_TITLE = "不安全的代理间通信 (Insecure Inter-Agent Communication)"
ASI08_TITLE = "级联代理故障 (Cascading Agent Failures)"
ASI09_TITLE = "人机信任滥用 (Human-Agent Trust Exploitation)"
ASI10_TITLE = "失控代理 (Rogue Agents)"

# 每项: (别名, 中文全称，用于文档)，KEY 保持一致即可复用现有 scenario id。
# 下划线用于展示用常量，不影响任何需要"无下划线"的运行时函数。
ASI = {
    "ASI01": ASI01_TITLE,
    "ASI02": ASI02_TITLE,
    "ASI03": ASI03_TITLE,
    "ASI04": ASI04_TITLE,
    "ASI05": ASI05_TITLE,
    "ASI06": ASI06_TITLE,
    "ASI07": ASI07_TITLE,
    "ASI08": ASI08_TITLE,
    "ASI09": ASI09_TITLE,
    "ASI10": ASI10_TITLE,
}

# 组件 / 位置 + 安全对照（供首页/README 表格复用，避免多份漂移）
ASI_COMP = {
    "ASI01": "seed/documents/*.md 隐藏载荷 + lab/graph.py / lab/framework",
    "ASI02": "lab/tools.py::query_orders / execute_python / send_email",
    "ASI03": "lab/tools.py::execute_python / 会话内冒充管理员工具集",
    "ASI04": "seed/documents/*.md / lab/tools.py（第三方脚本/规则即供应链）",
    "ASI05": "lab/tools.py::execute_python",
    "ASI06": "lab/memory.py::memory_search",
    "ASI07": "lab/multi_agent.py::multi-agent 消息通道",
    "ASI08": "lab/multi_agent.py::多 agent 级联 / lab/mock_llm.py 链式队列",
    "ASI09": "lab/graph.py HITL interrupt + 自动放行",
    "ASI10": "lab/tools.py::send_email → lab/outbox.jsonl",
}

ASI_FIX = {
    "ASI01": "输入净化 + 指令边界系统提示",
    "ASI02": "query_orders_safe 参数化 / send_email_safe 收件人白名单",
    "ASI03": "最小权限工具集 / 会话身份隔离 / 提权防护",
    "ASI04": "依赖脚本签名校验 + 规则来源审查",
    "ASI05": "受限沙箱 + 资源限制（对照安全值）",
    "ASI06": "memory_search_scoped（会话隔离）",
    "ASI07": "来源标记 + 消息签名 / 校验",
    "ASI08": "每 worker 独立预算 + 失败熔断（与级联下沉隔离）",
    "ASI09": "人工审批 + 摘要与原始动作双向绑定 + 二次确认",
    "ASI10": "出站管控 + 会话级行为边界",
}

# 离线的 legacy runner（lab/runner.py 的 run_demo 触发）当前实际可跑的场景 id
# （key 与 mock_llm 的 scenario 名保持一致）。
RUNNERS = {
    "asi01": "asi01_goal_hijack",
    "asi02": "asi02_tool_abuse",
    "asi03": "asi03_priv_abuse",
    "asi04": "asi04_supply_chain",
    "asi05": "asi05_code_exec",
    "asi06": "asi06_memory_poison",
    "asi07": "asi07_msg_spoof",
    "asi08": "asi08_cascade",
    "asi09": "asi09_hitl_bypass",
    "asi10": "asi10_rogue_agent",
}

# 单一 agent 场景（走 lab.graph.run_scenario + mock_llm）
SINGLE_KEYS = {
    "asi01",
    "asi02",
    "asi03",
    "asi04",
    "asi05",
    "asi06",
    "asi09",
    "asi10",
}
# 多 agent 场景（走 lab.multi_agent / 组合图）
MULTI_KEYS = {"asi07", "asi08"}


def asi_rows() -> list[tuple[str, str, str, str]]:
    """返回首页/README 表格所需的 (ASI, 漏洞名, 组件, 安全变体) 行。"""
    order = [
        "ASI01",
        "ASI02",
        "ASI03",
        "ASI04",
        "ASI05",
        "ASI06",
        "ASI07",
        "ASI08",
        "ASI09",
        "ASI10",
    ]
    return [(k, ASI[k], ASI_COMP.get(k, ""), ASI_FIX.get(k, "")) for k in order]
