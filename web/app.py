"""web/app.py — LangGraph 漏洞靶场 Web 界面（Flask）。

提供 ASI01–ASI10 演示、工具轨迹、游乐场和真实 LLM 配置。
邮件结果只写入本地 outbox；真实 LLM 是否联网由设置决定。
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

# 确保项目根目录在 sys.path 中，以便导入 lab 包
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lab import arena  # noqa: E402
from lab import flags  # noqa: E402
from lab import kb_map  # noqa: E402
from lab import levels  # noqa: E402
from lab import llmconf  # noqa: E402
from lab import selfaudit  # noqa: E402
from lab import solves  # noqa: E402
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
    "asi02": (
        os.path.join(ROOT, "docs", "asi02-principle.md"),
        "ASI02 工具误用与利用：原理与防护",
    ),
    "asi03": (
        os.path.join(ROOT, "docs", "asi03-principle.md"),
        "ASI03 身份与权限滥用：原理与防护",
    ),
    "asi04": (
        os.path.join(ROOT, "docs", "asi04-principle.md"),
        "ASI04 代理供应链：原理与防护",
    ),
    "asi05": (
        os.path.join(ROOT, "docs", "asi05-principle.md"),
        "ASI05 意外代码执行：原理与防护",
    ),
    "asi06": (
        os.path.join(ROOT, "docs", "asi06-principle.md"),
        "ASI06 记忆与上下文投毒：原理与防护",
    ),
    "asi07": (
        os.path.join(ROOT, "docs", "asi07-principle.md"),
        "ASI07 不安全的代理间通信：原理与防护",
    ),
    "asi08": (
        os.path.join(ROOT, "docs", "asi08-principle.md"),
        "ASI08 级联代理故障：原理与防护",
    ),
    "asi09": (
        os.path.join(ROOT, "docs", "asi09-principle.md"),
        "ASI09 人机信任滥用：原理与防护",
    ),
    "asi10": (
        os.path.join(ROOT, "docs", "asi10-principle.md"),
        "ASI10 失控代理：原理与防护",
    ),
}

# 运行日志（本地持久化，仅记录运行元数据，不记录 API key）
RUN_LOG = os.path.join(ROOT, "lab", "web", "run_log.jsonl")

app = Flask(__name__)

# 当前任务状态：保存这一次任务从用户输入到结束的完整事件历史。
# 新任务开始后整体替换，任务内部不会只保留最后一个工具调用。
_current_task_run: dict = {}
# 真实 LLM 模式配置（仅内存，不落盘）
# 配置来源优先级：本机文件（设置页保存的）> 环境变量 > 默认值。
# 本机文件优先，是因为用户是在网页上填的；环境变量作为无界面部署的入口。
_saved = llmconf.load()
_llm_config: dict = {
    "mode": _saved.get("mode") or os.environ.get("LAB_LLM_MODE", "real"),
    "provider": _saved.get("provider") or os.environ.get("LLM_PROVIDER", "openai"),
    "api_key": _saved.get("api_key") or os.environ.get("LLM_API_KEY", ""),
    "base_url": _saved.get("base_url") or os.environ.get("OPENAI_BASE_URL", ""),
    "model": _saved.get("model") or os.environ.get("LAB_MODEL", ""),
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
    """把当前 LLM 配置同步到进程环境变量。

    真实模式启用时写入 LLM_PROVIDER / LLM_API_KEY / OPENAI_BASE_URL / LAB_MODEL，
    供 **lab/framework/llm.py 的 OpenAICompatChatModel** 读取。
    注意不是 lab/mock_llm.py —— 那个模块只有确定性模拟，不读环境变量。

    mock 模式则清除上述变量。

    配置本身还会落盘到 lab/llm.json（见 lab/llmconf.py），
    这样服务重启后不必重填；api_key 是否落盘由设置页的"记住 key"决定。
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
# 模板全局变量
# ---------------------------------------------------------------------------


@app.context_processor
def inject_counts():
    """把靶场规模注入所有模板，便于侧边栏展示覆盖范围。

    靶场有 18 关（10 个 ASI + 8 个协议与运行时），侧边栏直接显示数量，
    让人一眼看出覆盖面，而不用点进关卡列表才数得清。
    """
    try:
        n = len(arena.CHALLENGES)
    except Exception:  # noqa: BLE001 - 侧边栏不应因统计失败而整页 500
        n = 0
    return {"arena_count": n}


# ---------------------------------------------------------------------------
# 页面路由
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    """渲染仪表盘页面（漏洞映射表 + 组件状态 + 快捷入口）。"""
    from lab.asi_map import asi_rows

    rows = asi_rows()
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
        asi_rows=rows,
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
    return render_template(
        "principle.html",
        title=title,
        body=body,
        doc_id=doc_id,
        error=None,
    )


@app.route("/kb")
def kbindex():
    """LLM 安全知识库总览：按分类列出全部文档。"""
    groups = [kb_map.kbgroup(g[0]) for g in kb_map.KB_GROUPS]
    return render_template(
        "kb.html",
        groups=groups,
        stats=kb_map.kbstats(),
        sources=kb_map.KB_SOURCES,
    )


@app.route("/kb/g/<gid>")
def kbgroup(gid: str):
    """知识库分类页：列出该分类下的全部文档。"""
    group = kb_map.kbgroup(gid)
    if not group:
        return render_template(
            "kbgroup.html",
            group={"id": "", "title": "未知分类", "en": "", "desc": f"分类不存在: {gid}", "docs": []},
            groups=[],
        ), 404
    groups = [kb_map.kbgroup(g[0]) for g in kb_map.KB_GROUPS]
    return render_template("kbgroup.html", group=group, groups=groups)


@app.route("/kb/<slug>")
def kbview(slug: str):
    """知识库文档页：将 docs/kb/*.md 渲染为 HTML。"""
    doc = kb_map.kbdoc(slug)
    if not doc:
        return render_template(
            "kbdoc.html",
            doc={"title": "未知文档", "en": "", "group": "", "group_zh": "", "slug": slug},
            body=f"<p>文档不存在: {slug}</p>",
        ), 404
    path = doc["file"]
    if not os.path.exists(path):
        return render_template(
            "kbdoc.html",
            doc=doc,
            body=f"<p>文档缺失: {path}</p>",
        ), 404
    with open(path, "r", encoding="utf-8") as f:
        body = render_markdown(f.read())
    return render_template("kbdoc.html", doc=doc, body=body)


@app.route("/selfaudit")
def selfaudit_page():
    """Agent 自评页：以本实例为对象运行只读自评，展示判定与证据。"""
    rows = selfaudit.audit()
    order = {"RISK": 0, "WARN": 1, "OK": 2}
    rows = sorted(rows, key=lambda r: order.get(r["level"], 3))
    counts = {"RISK": 0, "WARN": 0, "OK": 0}
    for r in rows:
        counts[r["level"]] = counts.get(r["level"], 0) + 1
    return render_template(
        "selfaudit.html",
        rows=rows,
        counts=counts,
        total=len(rows),
        declared=selfaudit.DECLARED,
        tools=selfaudit.TOOLS,
        doc=kb_map.kbdoc("case-self"),
        drill=kb_map.kbdoc("case-drill"),
    )


@app.route("/arena")
def arena_index():
    """可动手靶场：关卡列表与已获得 flag。"""
    return render_template(
        "arena_index.html",
        chs=arena.challenges(),
        lvs=levels.allrows(),
        got=solves.latest(),
    )


@app.route("/arena/<cid>")
def arena_chal(cid: str):
    """关卡入口：未指定难度时落到 low 档。

    注意：这里刻意**不**用 `defaults={"level": "low"}` 叠加在 arena_page 上。
    Werkzeug 会把同 endpoint 的 defaults 规则合并，导致 `/arena/x/low`
    被 308 重定向回 `/arena/x`。用独立入口更直白。
    """
    return arena_page(cid, "low")


@app.route("/arena/<cid>/<level>", methods=["GET", "POST"])
def arena_page(cid: str, level: str):
    """攻击台：提交载荷 → 按难度防御执行 → 判定 → 发 flag。

    这是本靶场与旧 demos 的关键区别：用户**自己构造载荷**，
    而不是跑一个预制剧本。
    """
    ch = arena.achall(cid)
    if not ch:
        return render_template(
            "arena_index.html",
            chs=arena.challenges(),
            lvs=levels.allrows(),
            got=solves.latest(),
        ), 404

    lv = levels.lv(level)
    if lv not in ch["levels"]:
        lv = "low"

    res = None
    vres = None
    payload = ""
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if action == "verify":
            cand = (request.form.get("candidate") or "").strip()
            vres = "校验通过：这是 %s / %s 的有效 flag" % (cid, lv) if flags.verify(cid, lv, cand) \
                else "校验失败：不匹配 %s / %s 的 flag" % (cid, lv)
        else:
            payload = request.form.get("payload") or ""
            res = arena.judge(cid, lv, payload)
            if res.get("pass") and res.get("flag"):
                solves.rec(cid, lv, res["flag"], note="via /arena")

    srcmap = {s["level"]: s for s in arena.sources(cid, lv)}
    return render_template(
        "arena.html",
        ch={"cid": cid, "title": ch["title"], "brief": ch["brief"],
            "goal": ch["goal"], "hint": ch["hint"],
            "surface": ch["levels"][lv].get("surface", "载荷")},
        lvs=levels.allrows(),
        level=lv,
        srcmap=srcmap,
        res=res,
        vres=vres,
        payload=payload,
        solved=solves.has(cid, lv),
    )


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
    cfg = dict(_llm_config)
    saved = llmconf.load()
    cfg["saved"] = bool(saved)
    cfg["remember"] = bool(saved.get("api_key"))
    cfg["store"] = os.path.basename(llmconf.path())
    return render_template("settings.html", config=cfg)


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
    """更新 LLM 配置并写入本机文件。

    请求体 JSON:
        mode: "mock" 或 "real"。
        provider / api_key / base_url / model: 真实模式参数（可选）。
        remember: 是否把 api_key 写入本机文件（默认 False，密钥不落盘）。

    返回:
        更新后的配置（api_key 以 *** 代替）。
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

    # 落盘：非敏感字段总是保存；api_key 仅在显式勾选时保存。
    keep = bool(data.get("remember"))
    if data.get("forget"):
        llmconf.forget(_llm_config)
        _llm_config["api_key"] = ""
        _apply_llm_config()
    else:
        llmconf.save(_llm_config, keep=keep)

    # 返回时隐藏 api_key
    safe = dict(_llm_config)
    safe["api_key"] = "***" if safe.get("api_key") else ""
    safe["remember"] = keep
    safe["store"] = os.path.basename(llmconf.path())
    safe["persisted"] = os.path.isfile(llmconf.path())
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
