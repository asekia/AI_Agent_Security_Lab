"""lab/selfaudit.py — 以本 Agent 实例为对象的安全自评。

用途：把 LLM 安全知识库中的风险条目，逐条对照到"当前这一个 Agent 实例"
的真实配置上，输出可复核的判定与证据，而不是泛泛的原则。

设计原则：
- 只读：不修改任何文件、不发起任何外部请求。
- 证据优先：每条判定都给出可复核的证据来源（文件与行，或运行时声明）。
- 不打印凭据值：涉及凭据时只统计数量与变量名。

函数命名保持短且无下划线：slurp / audit / show / main。
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 本会话的运行时声明（来自系统提示与运行时上下文，非推断）。
# 记录在这里是为了让判定可复核：如果这些前提变了，结论也要重算。
DECLARED = {
    "file_policy": "danger-full-access",
    "approval_prompts": "disabled",
    "shell": "pwsh",
    "workdir": ROOT,
}

# 本会话观测到的工具面（按能力归类，不逐一点名）。
TOOLS = [
    ("文件读取", "read / glob / grep", 3, "低"),
    ("文件写入", "write / edit", 2, "高"),
    ("命令执行", "pwsh（可执行任意程序）", 1, "高"),
    ("网络检索", "web_search", 1, "中"),
    ("浏览器控制", "chrome-mcp 系列（可驱动真实浏览器）", 1, "高"),
    ("任务委派", "subagent / workflow / ralph / agent_teams", 4, "高"),
    ("状态持久化", "evolve_*（跨会话记忆与技能）", 1, "中"),
    ("目标管理", "goal_* 系列", 1, "低"),
]


def slurp(path: str) -> str:
    """读取文本文件，失败时返回空串。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def find(text: str, pattern: str) -> str | None:
    """返回首个匹配行（已去空白），没有则返回 None。"""
    m = re.search(pattern, text, re.MULTILINE)
    return m.group(0).strip() if m else None


def check_app() -> list[dict]:
    """检查本仓库 Web 服务的监听地址。"""
    out = []
    src = slurp(os.path.join(ROOT, "web", "app.py"))
    run = slurp(os.path.join(ROOT, "run_web.py"))
    line = find(run, r"app\.run\(.*") or find(src, r".*run\(.*host.*")
    if not line:
        out.append({
            "id": "SVC-01", "title": "Web 服务监听地址无法确认", "level": "WARN",
            "evidence": "未在 web/app.py 或 run_web.py 中找到 app.run(...) 调用",
            "impact": "无法判断服务是否仅监听回环地址",
            "fix": "显式声明 host 与 port，并确认绑定 127.0.0.1",
        })
        return out
    loopback = "127.0.0.1" in line or "localhost" in line
    out.append({
        "id": "SVC-01", "title": "Web 服务监听范围", "level": "OK" if loopback else "RISK",
        "evidence": line,
        "impact": "仅回环监听时外部网络不可达；若为 0.0.0.0 则暴露给整个网络",
        "fix": "保持 127.0.0.1 绑定；需要对外时前置认证网关",
    })
    return out


def check_egress() -> list[dict]:
    """检查是否存在出站访问控制。"""
    src = slurp(os.path.join(ROOT, "lab", "framework", "defenses.py"))
    hint = find(src, r".*(allow|whitelist|白名单|domain).*") if src else None
    return [{
        "id": "NET-01", "title": "出站访问控制",
        "level": "WARN" if hint else "RISK",
        "evidence": ("defenses.py 中出现相关字样: " + hint) if hint
                    else "lab/framework/defenses.py 中未发现出站域名白名单或统一出口",
        "impact": "Agent 可执行命令且无出口限制时，任何被诱发的请求都能到达外部",
        "fix": "为命令执行与工具调用增加统一出口与域名白名单",
    }]


def check_memory() -> list[dict]:
    """检查记忆是否具备会话隔离。"""
    src = slurp(os.path.join(ROOT, "lab", "memory.py"))
    if not src:
        return [{
            "id": "MEM-01", "title": "记忆模块不可读", "level": "WARN",
            "evidence": "lab/memory.py 读取失败", "impact": "无法评估记忆隔离",
            "fix": "确认文件存在且可读",
        }]
    unscoped = bool(re.search(r"def\s+memory_search\s*\(", src))
    scoped = bool(re.search(r"def\s+memory_search_scoped\s*\(", src))
    if unscoped and scoped:
        return [{
            "id": "MEM-01", "title": "记忆存在未隔离的读取路径", "level": "RISK",
            "evidence": "lab/memory.py 同时定义 memory_search 与 memory_search_scoped",
            "impact": "未隔离的读取路径可跨会话取回内容，对应 ASI06 记忆投毒与跨会话泄露",
            "fix": "默认路径改为隔离版本；未隔离版本仅保留为教学对照并加显式告警",
        }]
    return [{
        "id": "MEM-01", "title": "记忆隔离", "level": "OK",
        "evidence": "未发现未隔离的读取路径", "impact": "-", "fix": "-",
    }]


def check_keys() -> list[dict]:
    """统计环境中凭据类变量（只记录名称与数量，绝不读取值）。"""
    pat = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE)
    names = sorted(n for n in os.environ if pat.search(n))
    if not names:
        return [{
            "id": "SEC-01", "title": "环境凭据暴露面", "level": "OK",
            "evidence": "环境中未发现凭据类变量名", "impact": "-", "fix": "-",
        }]
    shown = ", ".join(names[:6]) + (" 等" if len(names) > 6 else "")
    return [{
        "id": "SEC-01", "title": "环境凭据暴露面", "level": "RISK",
        "evidence": "检出 %d 个凭据类环境变量：%s" % (len(names), shown),
        "impact": "拥有命令执行能力的 Agent 可直接读取这些变量（对应 LLM02 / ASI03）",
        "fix": "改为按需短期下发；不让长生命周期的 Agent 进程继承凭据",
    }]


def check_tools() -> list[dict]:
    """对照工具面与最小权限原则。"""
    high = [t[0] for t in TOOLS if t[3] == "高"]
    return [{
        "id": "TOOL-01", "title": "工具面与最小权限", "level": "RISK",
        "evidence": "高影响能力 %d 类：%s" % (len(high), "、".join(high)),
        "impact": "写文件、执行命令、驱动浏览器、委派子代理同时具备，"
                  "一次被诱发的决策即可产生不可逆副作用（对应 LLM06 / ASI02）",
        "fix": "按任务裁剪工具集；高风险动作串行化并要求显式确认",
    }]


def check_delegate() -> list[dict]:
    """检查委派能力与本次会话中观测到的委派失效。"""
    return [{
        "id": "AGT-01", "title": "委派链路的可控性", "level": "RISK",
        "evidence": "具备 subagent / workflow / ralph / agent_teams 四类委派能力；"
                    "本会话中内容型子代理连续 5 次失败且未返回收尾信息",
        "impact": "子代理失败无收尾信息时无法定位原因，"
                  "且委派提示词本身构成对下游 Agent 的注入面（对应 ASI04 / ASI08）",
        "fix": "子代理必须具备失败原因回传；委派提示词纳入审计与模板化",
    }]


def check_untrusted() -> list[dict]:
    """检查是否把外部不可信内容直接纳入自身上下文与产出。"""
    return [{
        "id": "INJ-01", "title": "外部内容摄入", "level": "RISK",
        "evidence": "本会话读取并依据工作区外的 D:\\SAFE\\llm安全问题.txt 撰写知识库文档；"
                    "该文件内容已进入上下文并被写入仓库",
        "impact": "若该文件被篡改，其中的指令性文本会与用户指令同处一个上下文，"
                  "构成典型的间接注入路径（对应 LLM01 / ASI01 / ASI06）",
        "fix": "外部内容读取后先做归一化与指令性语句标记；"
               "产出物与来源分离，关键结论要求交叉验证",
    }]


def check_policy() -> list[dict]:
    """对照运行时策略声明。"""
    out = []
    fp = DECLARED["file_policy"]
    out.append({
        "id": "POL-01", "title": "文件沙箱策略",
        "level": "RISK" if fp == "danger-full-access" else "OK",
        "evidence": "运行时声明 file_policy=%s" % fp,
        "impact": "完整文件访问意味着工作区外路径同样可读写，"
                  "投毒或误改的范围不限于本项目（对应 ASI05）",
        "fix": "按任务收紧到 workspace-write；仅在确需时临时放宽",
    })
    ap = DECLARED["approval_prompts"]
    out.append({
        "id": "POL-02", "title": "审批提示状态",
        "level": "RISK" if ap == "disabled" else "OK",
        "evidence": "运行时声明 approval_prompts=%s" % ap,
        "impact": "无人工审批通道时，高风险动作缺少外部确认环节，"
                  "人机信任控制整体缺位（对应 ASI09）",
        "fix": "对高风险动作恢复确认机制，或改用显式双阶段流程",
    })
    return out


def audit() -> list[dict]:
    """汇总全部检查项。"""
    rows: list[dict] = []
    for fn in (check_policy, check_tools, check_app, check_egress,
               check_memory, check_keys, check_delegate, check_untrusted):
        rows.extend(fn())
    return rows


def show(rows: list[dict]) -> tuple[int, int, int]:
    """按级别打印结果，返回三类计数。"""
    order = {"RISK": 0, "WARN": 1, "OK": 2}
    rows = sorted(rows, key=lambda r: order.get(r["level"], 3))
    width = 72
    print("=" * width)
    print("Agent 实例安全自评（只读，不修改任何文件）")
    print("=" * width)
    counts = {"RISK": 0, "WARN": 0, "OK": 0}
    for r in rows:
        counts[r["level"]] = counts.get(r["level"], 0) + 1
        print("\n[%s] %s %s" % (r["level"], r["id"], r["title"]))
        print("  证据: %s" % r["evidence"])
        print("  影响: %s" % r["impact"])
        print("  处置: %s" % r["fix"])
    print("\n" + "=" * width)
    print("总计: RISK=%d  WARN=%d  OK=%d  共 %d 项"
          % (counts["RISK"], counts["WARN"], counts["OK"], len(rows)))
    print("=" * width)
    return counts["RISK"], counts["WARN"], counts["OK"]


def main() -> int:
    rows = audit()
    risk, warn, ok = show(rows)
    return 0 if risk == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
