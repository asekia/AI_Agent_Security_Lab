"""lab/levels.py — 难度分级定义（DVWA 式 low / medium / high）。

DVWA 的核心设计不是"有很多漏洞"，而是**同一个漏洞有多个防御强度的实现**：
low 能直接打通，medium 需要一点绕过技巧，high 基本打不通。
学习者通过对比两版源码理解"防御到底防住了什么"。

本模块只负责定义分级的语义与元数据；具体每关的实现由 lab/arena.py 调度。

函数命名保持短且无下划线: lv / levels / label / note。
"""
from __future__ import annotations

# 难度顺序（由易到难）
LEVELS = ("low", "medium", "high")

# 每级的中文名与设计意图
LABELS = {
    "low": "低",
    "medium": "中",
    "high": "高",
}

NOTES = {
    "low": "无防御，载荷原样进入模型上下文。",
    "medium": "有输入净化，但净化不覆盖全部绕过路径。",
    "high": "输入净化加出口闸门，两层都需穿过。",
}

# 每级的目标（用于页面展示）
GOALS = {
    "low": "构造最小可用 payload，拿到 flag",
    "medium": "找出净化规则的绕过点，再次拿到 flag",
    "high": "确认防御无法绕过",
}


def levels() -> tuple[str, ...]:
    """返回全部难度标识。"""
    return LEVELS


def lv(name: str) -> str:
    """规范化难度名；非法值回落到 low。"""
    n = (name or "").strip().lower()
    return n if n in LEVELS else "low"


def label(name: str) -> str:
    """返回难度的中文名。"""
    return LABELS.get(lv(name), "低")


def note(name: str) -> str:
    """返回该难度的设计说明。"""
    return NOTES.get(lv(name), "")


def goal(name: str) -> str:
    """返回该难度的学习目标。"""
    return GOALS.get(lv(name), "")


def allrows() -> list[dict]:
    """返回全部难度的元数据，供页面渲染。"""
    return [
        {"id": k, "label": LABELS[k], "note": NOTES[k], "goal": GOALS[k]}
        for k in LEVELS
    ]
