"""web/app.py — LangGraph 漏洞靶场 Web 界面（Flask）。

一个本地、离线的中文 Web 界面，用于：
- 查看 ASI01-ASI10 漏洞映射表
- 运行三个强制攻击演示并查看结构化工具调用轨迹
- 在"游乐场"中输入自定义提示词驱动 agent
- 检查本地 sink（outbox.jsonl / memory_store.json / checkpoints）
- 切换 mock / 真实 LLM 模式

安全约束：
- 仅绑定 127.0.0.1（绝不绑定 0.0.0.0）
- 无外部 CDN / 无网络抓取（所有资源本地）
- 真实 LLM 模式仅在用户显式开启时才会发起网络调用
- API key 仅保存在进程内存（os.environ），绝不写入磁盘

注意：本界面仅用于**授权**的安全教学演示。
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, send_file

# 确保项目根目录在 sys.path 中，以便导入 lab 包
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lab import runner  # noqa: E402
from lab.banner import print_banner  # noqa: E402
from lab.framework import get_framework  # noqa: E402
from lab.framework.chat_asi01 import reset, savefile, turn  # noqa: E402
from web.markdown import render_markdown  # noqa: E402

# 原理文档注册表：doc_id → (markdown 路径, 页面标题)
DOCS = {
    "asi01": (
        os.path.join(ROOT, "docs", "asi01-principle.md"),
        "ASI01 提示注入 · 目标劫持：原理与防护",
    ),
}

# 运行日志（本地持久化，仅记录运行元数据，不记录 API key）
RUN_LOG = os.path.join(ROOT, "lab", "web", "run_log.jsonl")

app = Flask(__name__)

# 当前任务状态：保存这一次任务从用户输入到结束的完整事件历史。
# 新任务开始后整体替换，任务内部不会只保留最后一个工具调用。
_current_task_run: dict = {}
# 真实 LLM 模式配置（仅内存，不落盘）
_llm_config: dict = {
    "mode": os.environ.get("LAB_LLM_MODE", "real"),  # real | mock
    "provider": os.environ.get("LLM_PROVIDER", "openai"),
    "api_key": os.environ.get("LLM_API_KEY", ""),
    "base_url": os.environ.get("OPENAI_BASE_URL", ""),
    "model": os.environ.get("LAB_MODEL", ""),
}


def _now_iso() -> str:
    """返回当前 UTC 时间的 ISO 格式字符串。"""
    return datetime.now(timezone.utc).isoformat()


def _log_run(entry: dict) -> None:
    """将一次运行记录追加到本地 run_log.jsonl。

    参数:
        entry: 运行记录字典（timestamp / mode / prompt / exfil 等）。
    """
    os.makedirs(os.path.dirname(RUN_LOG), exist_ok=True)
    with open(RUN_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _read_run_log(limit: int = 100) -> list[dict]:
    """读取本地运行历史 run_log.jsonl。

    参数:
        limit: 最多返回的条数。

    返回:
        运行记录列表（最新在前）。
    """
    if not os.path.exists(RUN_LOG):
        return []
    entries: list[dict] = []
    with open(RUN_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries[-limit:][::-1]


def _detect_exfil(outbox_entries: list[dict]) -> bool:
    """判断本次运行是否发生了向 attacker@evil.lab 的外泄。

    参数:
        outbox_entries: 本次运行写入的外发记录。

    返回:
        是否检测到外泄。
    """
    for e in outbox_entries:
        if "attacker@evil.lab" in str(e.get("to", "")):
            return True
    return False


def _apply_llm_config() -> None:
    """将内存中的 LLM 配置写入进程环境变量（仅内存，不落盘）。

    真实模式启用时，将 API key / base url / model 写入 os.environ，
    供 lab.mock_llm.get_llm 读取。mock 模式则清除相关环境变量。
    """
    if _llm_config["mode"] == "real":
        os.environ["LLM_PROVIDER"] = _llm_config.get("provider", "openai")
        if _llm_config.get("api_key"):
            os.environ["LLM_API_KEY"] = _llm_config["api_key"]
        if _llm_config.get("base_url"):
            os.environ["OPENAI_BASE_URL"] = _llm_config["base_url"]
        if _llm_config.get("model"):
            os.environ["LAB_MODEL"] = _llm_config["model"]
    else:
        for k in ("LLM_PROVIDER", "LLM_API_KEY", "OPENAI_BASE_URL", "LAB_MODEL"):
            os.environ.pop(k, None)


# ---------------------------------------------------------------------------
# 页面路由
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    """渲染仪表盘页面（漏洞映射表 + 组件状态 + 快捷入口）。"""
    asi_rows = [
        ("ASI01", "提示注入 (Prompt Injection)", "seed/documents/support_kb.md 隐藏载荷 + lab/graph.py", "输入净化 / 指令边界"),
        ("ASI02", "工具滥用 (Tool Misuse)", "lab/tools.py::send_email", "send_email_safe（收件人白名单）"),
        ("ASI03", "工具调用链劫持 (Tool Chaining)", "lab/graph.py::_execute_tool", "工具调用审计"),
        ("ASI04", "过度授权 (Over-Authorization)", "lab/tools.py::execute_python", "最小权限沙箱"),
        ("ASI05", "沙箱逃逸 (Sandbox Escape)", "lab/tools.py::execute_python", "受限执行环境"),
        ("ASI06", "记忆投毒 (Memory Poisoning)", "lab/memory.py::memory_search", "memory_search_scoped（会话隔离）"),
        ("ASI07", "消息伪造 (Message Spoofing)", "lab/multi_agent.py", "来源认证 / 消息签名"),
        ("ASI08", "无界消耗 (Unbounded Consumption)", "lab/multi_agent.py", "enforce_budget（step 预算）"),
        ("ASI09", "审批滥用 (Approval Abuse)", "lab/graph.py HITL + demo 自动批准", "人工审批 + 摘要校验"),
        ("ASI10", "数据外泄 (Data Exfiltration)", "lab/tools.py::send_email → outbox.jsonl", "出站过滤 / 数据脱敏"),
    ]
    # 组件状态
    venv_ok = os.path.exists(os.path.join(ROOT, ".venv", "Scripts", "python.exe"))
    deps_ok = True
    try:
        import langgraph  # noqa: F401
        import flask  # noqa: F401
    except ImportError:
        deps_ok = False
    return render_template(
        "index.html",
        asi_rows=asi_rows,
        venv_ok=venv_ok,
        deps_ok=deps_ok,
        llm_mode=_llm_config["mode"],
    )


@app.route("/asi/<demo_id>")
def asi_page(demo_id: str):
    """渲染单个 ASI 演示页面（含运行按钮与轨迹展示）。"""
    demo = runner.DEMOS.get(demo_id)
    if not demo:
        return render_template("asi.html", demo=None, error="未知演示 ID"), 404
    return render_template("asi.html", demo=demo, error=None)


@app.route("/playground")
def playground():
    """渲染游乐场页面（自定义提示词 + 模式选择 + 隐藏载荷揭示）。"""
    return render_template("playground.html", llm_mode=_llm_config["mode"])


@app.route("/agent")
def agent_page():
    """渲染 Agent 框架页面（真实 AI 模块接入 + ASI01 场景）。"""
    return render_template(
        "agent.html",
        scenarios=get_framework().list_scenarios(),
        llm_mode=_llm_config["mode"],
    )


@app.route("/asi01/chat")
def asichat():
    """渲染 ASI01 聊天小靶场。"""
    return render_template(
        "asi01_chat.html",
        llm_mode=_llm_config["mode"],
    )


@app.route("/principle/<doc_id>")
def principle_page(doc_id: str):
    """渲染原理文档页（将 docs/*.md 渲染为 HTML）。"""
    doc = DOCS.get(doc_id)
    if not doc:
        return render_template("principle.html", error=f"未知文档: {doc_id}", title="未知文档"), 404
    path, title = doc
    if not os.path.exists(path):
        return render_template("principle.html", error=f"文档缺失: {path}", title=title), 404
    with open(path, "r", encoding="utf-8") as f:
        body = render_markdown(f.read())
    return render_template("principle.html", title=title, body=body, doc_id=doc_id, error=None)


@app.route("/docs/<path:filename>")
def docs_file(filename: str):
    """下载 docs/ 下的原始 Markdown 文档。"""
    safe = os.path.basename(filename)
    path = os.path.join(ROOT, "docs", safe)
    if not os.path.isfile(path):
        return jsonify({"error": "文件不存在"}), 404
    return send_file(path, as_attachment=False, mimetype="text/markdown; charset=utf-8")


@app.route("/trace")
def trace_page():
    """渲染当前任务从输入到结束的完整事件与工具调用历史。"""
    return render_template(
        "trace.html",
        run=_current_task_run,
        run_json=json.dumps(_current_task_run, ensure_ascii=False),
    )


@app.route("/log")
def log_page():
    """渲染攻击历史页面。"""
    return render_template("log.html", runs=_read_run_log())


@app.route("/settings")
def settings_page():
    """渲染设置页面（mock / 真实 LLM 切换）。"""
    return render_template("settings.html", config=_llm_config)


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------


@app.route("/api/run/<demo_id>", methods=["POST"])
def api_run_demo(demo_id: str):
    """运行指定演示并返回结构化轨迹。

    参数:
        demo_id: 演示标识（asi01 / asi06 / asi07）。

    返回:
        JSON，含 trace / final / outbox_entries / exfil。
    """
    global _current_task_run
    try:
        result = runner.run_demo(demo_id)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500

    exfil = _detect_exfil(result.get("outbox_entries", []))
    result["exfil"] = exfil
    result["timestamp"] = _now_iso()
    result["demo_id"] = demo_id
    _current_task_run = result

    _log_run(
        {
            "timestamp": result["timestamp"],
            "mode": result["mode"],
            "prompt": result.get("scenario", ""),
            "demo_id": demo_id,
            "exfil": exfil,
            "steps": len(result.get("trace", [])),
        }
    )
    return jsonify(result)


@app.route("/api/playground", methods=["POST"])
def api_playground():
    """运行游乐场自定义提示词并返回结构化轨迹。

    请求体 JSON:
        prompt: 用户提示词。
        mode: "single" 或 "multi"。

    返回:
        JSON，含 trace / final / outbox_entries / exfil。
    """
    global _current_task_run
    data = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()
    mode = str(data.get("mode", "single")).strip()
    if not prompt:
        return jsonify({"error": "提示词不能为空"}), 400

    try:
        if mode == "multi":
            result = runner.run_multi_agent(prompt)
        else:
            result = runner.run_single_agent(prompt)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500

    exfil = _detect_exfil(result.get("outbox_entries", []))
    result["exfil"] = exfil
    result["timestamp"] = _now_iso()
    result["demo_id"] = None
    _current_task_run = result

    _log_run(
        {
            "timestamp": result["timestamp"],
            "mode": result["mode"],
            "prompt": prompt,
            "demo_id": None,
            "exfil": exfil,
            "steps": len(result.get("trace", [])),
        }
    )
    return jsonify(result)


def _as_bool(value: object) -> bool:
    """将 JSON 布尔/字符串解析为布尔值。"""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


@app.route("/api/asi01/chat/reset", methods=["POST"])
def aireset():
    """重置 ASI01 聊天会话。"""
    data = request.get_json(silent=True) or {}
    session = str(data.get("session", data.get("session_id", ""))).strip()
    if session:
        reset(session)
    return jsonify({"ok": True})


@app.route("/api/asi01/chat/file", methods=["POST"])
def aifile():
    """在 requirements/asi01/ 中写入用户提供的 Markdown。"""
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    text = str(data.get("text", ""))
    result = savefile(name, text)
    return jsonify({"result": result}), 400 if result.startswith("[error]") else 200


@app.route("/api/asi01/chat/turn", methods=["POST"])
def aichat():
    """处理 ASI01 聊天消息并按文件内容执行动作。"""
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"error": "消息不能为空"}), 400
    session = str(data.get("session", data.get("session_id", ""))).strip() or None
    defense = _as_bool(data.get("defense", False))
    approve = _as_bool(data.get("approve", True))
    backend = "real"
    cfg = {
        "base_url": str(data.get("base_url") or _llm_config.get("base_url") or "").strip(),
        "api_key": str(data.get("api_key") or _llm_config.get("api_key") or "").strip(),
        "model": str(data.get("model") or _llm_config.get("model") or "").strip(),
    }
    try:
        result = turn(
            message,
            session=session,
            defense=defense,
            approve=approve,
            backend=backend,
            cfg=cfg,
        )
    except Exception as exc:  # noqa: BLE001 - 靶场返回可读错误
        return jsonify({"error": f"聊天运行失败: {type(exc).__name__}: {exc}"}), 500
    return jsonify(result)


@app.route("/api/agent/scenarios", methods=["GET"])
def api_agent_scenarios():
    """返回 Agent 框架的全部场景元数据（含 wired/stub 状态）。"""
    return jsonify(get_framework().list_scenarios())


@app.route("/api/agent/run", methods=["POST"])
def api_agent_run():
    """通过 Agent 框架运行指定场景（当前仅 ASI01 已接入）。

    请求体 JSON:
        scenario:  场景 id（默认 asi01）。
        backend:   "mock"（默认）或 "real"（OpenAI 兼容端点）。
        defense:   是否启用防御变体（默认 false）。
        auto_approve: 危险工具是否自动批准（默认 true）。
        base_url / api_key / model: 真实后端参数（可选，缺省回退到设置页/环境变量）。

    返回:
        JSON，含 trace / verdict / outbox_entries / exfil。
    """
    global _current_task_run
    data = request.get_json(silent=True) or {}
    scenario_id = str(data.get("scenario", "asi01")).strip()
    backend = str(data.get("backend", "mock")).strip()
    defense = _as_bool(data.get("defense", False))
    auto_approve = _as_bool(data.get("auto_approve", True))

    llm_cfg = None
    if backend in ("real", "openai", "openai-compatible", "openai_compat"):
        llm_cfg = {
            "base_url": str(data.get("base_url") or _llm_config.get("base_url") or "").strip(),
            "api_key": str(data.get("api_key") or _llm_config.get("api_key") or "").strip(),
            "model": str(data.get("model") or _llm_config.get("model") or "").strip(),
        }

    try:
        result = get_framework().run(
            scenario_id,
            backend=backend,
            defense=defense,
            auto_approve=auto_approve,
            llm_cfg=llm_cfg,
        )
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 500

    if result.get("error"):
        return jsonify(result), 400

    result["timestamp"] = _now_iso()
    result["demo_id"] = scenario_id
    _current_task_run = result

    _log_run(
        {
            "timestamp": result["timestamp"],
            "mode": f"agent:{backend}",
            "prompt": result.get("scenario", scenario_id),
            "demo_id": scenario_id,
            "defense": defense,
            "hijacked": result.get("verdict", {}).get("hijacked", False),
            "exfil": result.get("exfil", False),
            "steps": len(result.get("trace", [])),
        }
    )
    return jsonify(result)


@app.route("/api/trace", methods=["GET"])
def api_trace():
    """返回当前任务的完整事件与工具调用历史。"""
    return jsonify(_current_task_run)


@app.route("/api/log", methods=["GET"])
def api_log():
    """返回本地运行历史。"""
    return jsonify(_read_run_log())


@app.route("/api/settings", methods=["POST"])
def api_settings():
    """更新 LLM 模式配置（仅内存，不落盘）。

    请求体 JSON:
        mode: "mock" 或 "real"。
        provider / api_key / base_url / model: 真实模式参数（可选）。

    返回:
        更新后的配置（不含 api_key 明文）。
    """
    global _llm_config
    data = request.get_json(silent=True) or {}
    mode = str(data.get("mode", "mock")).strip()
    if mode not in ("mock", "real"):
        return jsonify({"error": "mode 必须为 mock 或 real"}), 400

    _llm_config["mode"] = mode
    if mode == "real":
        _llm_config["provider"] = str(data.get("provider", "openai")).strip() or "openai"
        if data.get("api_key"):
            _llm_config["api_key"] = str(data["api_key"]).strip()
        if data.get("base_url"):
            _llm_config["base_url"] = str(data["base_url"]).strip()
        if data.get("model"):
            _llm_config["model"] = str(data["model"]).strip()
    _apply_llm_config()

    # 返回时隐藏 api_key
    safe = dict(_llm_config)
    safe["api_key"] = "***" if safe.get("api_key") else ""
    return jsonify(safe)


@app.route("/api/documents/<name>", methods=["GET"])
def api_documents(name: str):
    """读取 seed/documents/ 下的文档，可选揭示隐藏注入载荷。

    参数:
        name: 文档文件名。
        reveal: 查询参数，为 "true" 时返回隐藏载荷分析。

    返回:
        JSON，含 name / content / hidden（可选）。
    """
    reveal = request.args.get("reveal", "false").lower() == "true"
    try:
        content = runner.read_document(name)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 404

    resp: dict = {"name": name, "content": content}
    if reveal:
        resp["hidden"] = runner.extract_hidden_payloads(content)
    return jsonify(resp)


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------


def main() -> None:
    """启动 Flask 开发服务器（仅绑定 127.0.0.1）。"""
    print_banner()
    print("=" * 60)
    print("  LangGraph 漏洞靶场 Web 界面")
    print("  请在浏览器打开: http://127.0.0.1:5000")
    print("  注意: 仅绑定 127.0.0.1，绝不暴露到网络。")
    print("=" * 60)
    # 仅绑定 127.0.0.1 —— 绝不使用 0.0.0.0
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
