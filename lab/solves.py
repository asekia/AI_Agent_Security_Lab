"""lab/solves.py — 通关记录（哪些关卡在哪个难度已拿到 flag）。

记录落在 lab/solves.jsonl，一行一条，便于审计与回看历史。
判定本身在 lab/arena.py；本模块只负责"记下来"与"读出来"。

函数命名保持短且无下划线: rec / allrows / has / path。
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "solves.jsonl")


def path() -> str:
    """返回通关记录文件路径。"""
    return STORE


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
    with open(STORE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def allrows() -> list[dict]:
    """读取全部通关记录。"""
    if not os.path.isfile(STORE):
        return []
    rows = []
    with open(STORE, "r", encoding="utf-8") as f:
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
