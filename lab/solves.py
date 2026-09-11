"""lab/solves.py — 通关记录（哪些关卡在哪个难度已拿到 flag）。

记录落在 lab/solves.jsonl，一行一条，便于审计与回看历史。
判定本身在 lab/arena.py；本模块只负责"记下来"与"读出来"。

**测试隔离**：环境变量 LAB_SOLVES 可覆盖记录路径。
测试必须指向临时文件 —— 否则跑一次测试就会把用户从没打过的关卡
标成"已通关"，页面上的进度就成了假的。

函数命名保持短且无下划线: rec / allrows / has / path。
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "solves.jsonl")
ENV = "LAB_SOLVES"


def path() -> str:
    """返回通关记录路径（每次调用都读环境变量，便于测试隔离）。"""
    return os.environ.get(ENV) or DEFAULT


def rec(cid: str, level: str, flag: str, note: str = "") -> dict:
    """追加一条通关记录。

    参数:
        cid: 关卡 id。
        level: 难度。
        flag: 该难度签发的 flag。
        note: 可选备注。

    返回:
        写入的记录字典。
    """
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "cid": cid,
        "level": level,
        "flag": flag,
        "note": note,
    }
    with open(path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def allrows() -> list[dict]:
    """读取全部通关记录。"""
    f0 = path()
    if not os.path.isfile(f0):
        return []
    rows = []
    with open(f0, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:  # noqa: BLE001 - 跳过损坏行而不是整体失败
                continue
    return rows


def latest() -> list[dict]:
    """按关卡+难度去重，返回每个组合最近一次通关（用于列表页展示）。"""
    seen = {}
    for r in allrows():
        seen[(r.get("cid"), r.get("level"))] = r
    return sorted(seen.values(), key=lambda r: (r.get("cid", ""), r.get("level", "")))


def has(cid: str, level: str) -> bool:
    """判断某关卡某难度是否已通关。"""
    return any(r.get("cid") == cid and r.get("level") == level for r in allrows())
