"""lab/flags.py — 关卡 flag 的签发与校验（靶场地基）。

设计目标（对齐 DVWA / sqli-labs 的过关机制）
    每关每个难度有**唯一且确定**的 flag：同一关卡同一难度永远得到同一个
    flag，但脱离本机密钥无法伪造或猜出。

实现
    flag = "flag{" + HMAC-SHA256(key, "<cid>:<level>")[:16] + "}"
    key 首次运行时随机生成并落盘，不进版本库。

为什么不用"随机 flag"
    随机会让"记录已通关"无法跨会话校验。确定性 + 本地密钥既保证可复核，
    又保证不可猜测。

函数命名保持短且无下划线: mint / verify / award / keypath。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".flagkey")


def keypath() -> str:
    """返回 flag 密钥文件路径。"""
    return KEYFILE


def _key() -> bytes:
    """读取本地 flag 密钥；不存在则生成。

    密钥只落在本机，权限尽量收紧，且不应进入版本库。
    """
    if os.path.isfile(KEYFILE):
        with open(KEYFILE, "rb") as f:
            data = f.read().strip()
        if data:
            return data
    data = secrets.token_bytes(32)
    with open(KEYFILE, "wb") as f:
        f.write(data)
    try:
        os.chmod(KEYFILE, 0o600)
    except OSError:
        pass  # Windows 上 chmod 语义有限，失败不阻断
    return data


def mint(cid: str, level: str) -> str:
    """为指定关卡与难度签发确定的 flag。

    参数:
        cid: 关卡 id（如 "asi01"）。
        level: 难度（low / medium / high）。

    返回:
        形如 flag{16 位十六进制} 的字符串。
    """
    msg = ("%s:%s" % (cid, level)).encode("utf-8")
    digest = hmac.new(_key(), msg, hashlib.sha256).hexdigest()[:16]
    return "flag{%s}" % digest


def verify(cid: str, level: str, candidate: str) -> bool:
    """校验候选 flag 是否正确（定时安全比较）。

    参数:
        cid: 关卡 id。
        level: 难度。
        candidate: 用户提交的 flag 字符串。

    返回:
        是否正确。
    """
    if not candidate:
        return False
    return hmac.compare_digest(mint(cid, level).strip(), candidate.strip())


def award(cid: str, level: str) -> dict:
    """判定通过时的发奖结果。

    返回:
        含 flag 与提示信息的字典。
    """
    return {
        "cid": cid,
        "level": level,
        "flag": mint(cid, level),
        "message": "关卡通过：%s / %s" % (cid, level),
    }
