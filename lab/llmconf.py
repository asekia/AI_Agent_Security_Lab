"""lab/llmconf.py — LLM 配置的本机持久化。

**为什么需要**：原先 Web 设置页只把配置写进进程内存（`_llm_config` + 环境变量），
服务一重启就全没了。用户刚在网页上填好 key，重启后静默失效，
表现为 ASI01 对话报一个与配置无关的错误 —— 极难排查。

**安全取舍**：api_key 是密钥，默认**不落盘**。
只有非敏感字段（mode / provider / base_url / model）会自动保存；
api_key 必须由用户在设置页显式勾选"记住 key"才会写入本机文件。

存储位置 lab/llm.json，已 gitignore，不进版本库。

函数命名保持短且无下划线: path / load / save。
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "llm.json")
ENV = "LAB_LLM_CONF"

# 允许持久化的字段。api_key 单独控制，见 save() 的 keep 参数。
FIELDS = ("mode", "provider", "base_url", "model")


def path() -> str:
    """返回配置文件路径（每次调用都读环境变量，便于测试隔离）。"""
    return os.environ.get(ENV) or FILE


def load() -> dict:
    """读取本机配置。文件不存在或损坏时返回空字典。"""
    f0 = path()
    if not os.path.isfile(f0):
        return {}
    try:
        with open(f0, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001 - 配置损坏不应让服务起不来
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def save(cfg: dict, keep: bool = False) -> dict:
    """保存配置到本机文件。

    参数:
        cfg: 配置字典（mode / provider / base_url / model / api_key）。
        keep: 是否把 api_key 一并写入。默认 False，即密钥不落盘。

    返回:
        实际写入的字典（不含 api_key 明文时为占位）。
    """
    out = {k: str(cfg.get(k, "")) for k in FIELDS}
    if keep and cfg.get("api_key"):
        out["api_key"] = str(cfg["api_key"])
    with open(path(), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    return out


def forget(cfg: dict | None = None) -> dict:
    """只清除 api_key，保留其余配置。

    设置页的按钮文案承诺"Base URL 与 Model 会保留"，所以这里不能
    直接删文件 —— 那会连端点配置一起丢掉，用户得重新填一遍。

    参数:
        cfg: 当前内存配置；给了就据此重写文件，没给就只从文件里摘掉 key。

    返回:
        清除后仍保留的配置。
    """
    rest = {k: str((cfg or load()).get(k, "")) for k in FIELDS}
    with open(path(), "w", encoding="utf-8") as f:
        json.dump(rest, f, ensure_ascii=False, indent=1)
    return rest
