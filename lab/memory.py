"""lab/memory.py — 跨会话向量记忆（ASI06 攻击面）。

实现一个轻量、完全离线的 TF-IDF + 余弦相似度记忆系统，持久化到 JSON 文件。
- memory_write(text, session_id): 写入一条记忆
- memory_search(query, session_id): 检索记忆
  # [VULN] ASI06: 检索默认不按 session 隔离 —— 跨会话泄露 + 记忆投毒。
- memory_search_scoped(query, session_id): 安全变体，仅检索本会话记忆。
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEMORY_FILE = os.path.join(ROOT, "lab", "memory_store.json")

_TOKEN_RE = re.compile(r"[a-zA-Z0-9\u4e00-\u9fff]+")


def _tokenize(text: str) -> list[str]:
    """将文本切分为 token 列表（英文按词，中文按单字）。"""
    tokens: list[str] = []
    for part in _TOKEN_RE.findall(text):
        if re.fullmatch(r"[a-zA-Z0-9]+", part):
            tokens.append(part.lower())
        else:
            # 中文按单字切分，便于子串匹配
            tokens.extend(list(part))
    return tokens


class VectorMemory:
    """基于 TF-IDF + 余弦相似度的离线向量记忆存储。"""

    def __init__(self, path: str = MEMORY_FILE) -> None:
        """初始化记忆存储，加载已有 JSON 数据。"""
        self.path = path
        self._records: list[dict] = []
        self._load()

    def _load(self) -> None:
        """从磁盘加载记忆记录。"""
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self._records = json.load(f)

    def _save(self) -> None:
        """将记忆记录持久化到磁盘。"""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._records, f, ensure_ascii=False, indent=2)

    def memory_write(self, text: str, session_id: str) -> str:
        """写入一条记忆（跨会话共享存储）。

        参数:
            text: 记忆内容。
            session_id: 来源会话标识。

        返回:
            写入结果描述。
        """
        self._records.append({"text": text, "session_id": session_id})
        self._save()
        return f"记忆已写入 (session={session_id})"

    def memory_search(self, query: str, session_id: str, top_k: int = 3) -> str:
        """检索记忆。

        # [VULN] ASI06: 检索不按 session 隔离 —— 返回所有会话的记忆，
        # 导致跨会话信息泄露，且可被其他会话投毒的记忆"劫持"。
        # 攻击者可在会话 A 写入一条伪装成"系统偏好"的记忆，
        # 会话 B 检索时会被该记忆误导。

        参数:
            query: 检索查询。
            session_id: 当前会话标识（此处仅用于展示，不用于过滤）。
            top_k: 返回条数。

        返回:
            检索到的记忆文本（JSON 字符串）。
        """
        if not self._records:
            return "[]"
        scored = []
        for rec in self._records:
            score = self._cosine(query, rec["text"])
            scored.append((score, rec))
        scored.sort(key=lambda x: x[0], reverse=True)
        top = [r for s, r in scored[:top_k] if s > 0]
        return json.dumps(top, ensure_ascii=False)

    def memory_search_scoped(self, query: str, session_id: str, top_k: int = 3) -> str:
        """安全变体：仅检索当前会话的记忆。

        参数:
            query: 检索查询。
            session_id: 当前会话标识（用于过滤）。
            top_k: 返回条数。

        返回:
            检索到的本会话记忆（JSON 字符串）。
        """
        scoped = [r for r in self._records if r["session_id"] == session_id]
        if not scoped:
            return "[]"
        scored = []
        for rec in scoped:
            score = self._cosine(query, rec["text"])
            scored.append((score, rec))
        scored.sort(key=lambda x: x[0], reverse=True)
        top = [r for s, r in scored[:top_k] if s > 0]
        return json.dumps(top, ensure_ascii=False)

    @staticmethod
    def _cosine(a: str, b: str) -> float:
        """计算两个文本的 TF-IDF 加权余弦相似度。"""
        ta, tb = _tokenize(a), _tokenize(b)
        if not ta or not tb:
            return 0.0
        ca, cb = Counter(ta), Counter(tb)
        vocab = set(ca) | set(cb)
        # 简化 IDF：使用文档频率近似（此处仅两篇文档）
        df = {w: (1 if w in ca else 0) + (1 if w in cb else 0) for w in vocab}
        idf = {w: math.log(2.0 / df[w]) + 1.0 for w in vocab}
        va = {w: ca[w] * idf[w] for w in ca}
        vb = {w: cb[w] * idf[w] for w in cb}
        dot = sum(va.get(w, 0.0) * vb.get(w, 0.0) for w in vocab)
        na = math.sqrt(sum(v * v for v in va.values()))
        nb = math.sqrt(sum(v * v for v in vb.values()))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)
