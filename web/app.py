"""web/app.py — agent安全笔记 Web 界面（Flask）。

提供 ASI01–ASI10 演示、工具轨迹、游乐场和真实 LLM 配置。
邮件结果只写入本地 outbox；真实 LLM 是否联网由设置决定。
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

# 确保项目根目录在 sys.path 中，以便导入 lab 包
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lab import kb_map  # noqa: E402
from lab import learn  # noqa: E402
from lab import runner  # noqa: E402
from lab.banner import print_banner  # noqa: E402
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

app = Flask(__name__)

# /watermark 整页结果缓存（确定性计算，同参数同结果；上限 8 份防膨胀）。
# 当前任务状态：保存这一次任务从用户输入到结束的完整事件历史。
# 新任务开始后整体替换，任务内部不会只保留最后一个工具调用。
_current_task_run: dict = {}


def _now_iso() -> str:
    """返回当前 UTC 时间的 ISO 格式字符串。"""
    return datetime.now(timezone.utc).isoformat()


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


# ---------------------------------------------------------------------------
# 模板全局变量
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 页面路由
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    """渲染仪表盘页面（学习入口 + ASI 主题矩阵 + 组件状态）。"""
    from lab.asi_map import ASI
    from lab.runner import DEMOS

    topics = []
    for n in range(1, 11):
        tid = f"asi{n:02d}"
        demo = DEMOS.get(tid, {})
        topics.append(
            {
                "id": tid,
                "name": ASI[tid.upper()],
                "desc": demo.get("desc", ""),
            }
        )
    return render_template(
        "index.html",
        topics=topics,
        learn_paths=learn.allrows(),
    )


@app.route("/asi/<demo_id>")
def asi_page(demo_id: str):
    """渲染单个 ASI 演示页面（含运行按钮与轨迹展示）。"""
    demo = runner.DEMOS.get(demo_id)
    if not demo:
        return render_template("asi.html", demo=None, error="未知演示 ID"), 404
    return render_template("asi.html", demo=demo, error=None)


# 每个主题页 curated 的相关知识库条目（slug 顺序即展示顺序）
TOPIC_KB = {
    "asi01": ["inj-direct", "inj-indirect", "def-input"],
    "asi02": ["agt-agency", "inj-tool", "base-assets"],
    "asi03": ["agt-agency", "agt-trust", "base-assets"],
    "asi04": ["base-chain", "prot-mcp", "inf-mlops"],
    "asi05": ["prot-file", "def-arch", "inf-cve"],
    "asi06": ["ctx-memory", "ctx-overflow", "mod-embed"],
    "asi07": ["agt-multi", "prot-a2a", "def-arch"],
    "asi08": ["agt-multi", "def-arch", "def-test"],
    "asi09": ["agt-trust", "jail-emotion", "def-test"],
    "asi10": ["agt-agency", "def-arch", "def-test"],
}

_H2_RE = re.compile(r"<h2>(.*?)</h2>")


def _with_toc(html: str) -> tuple[str, list[dict]]:
    """给渲染后的 HTML 的 h2 注入锚点 id，返回 (新 HTML, 目录条目)。"""
    toc: list[dict] = []
    counter = {"n": 0}

    def _repl(m: re.Match) -> str:
        counter["n"] += 1
        sec_id = f"sec-{counter['n']}"
        toc.append({"id": sec_id, "text": m.group(1)})
        return f'<h2 id="{sec_id}">{m.group(1)}</h2>'

    return _H2_RE.sub(_repl, html), toc


@app.route("/topic/<asi>")
def topic_page(asi: str):
    """主题整合页（PortSwigger 式）：概览 → 目录 → 原理全文 → 动手区 → 相关知识。"""
    from lab.asi_map import ASI

    if asi.upper() not in ASI:
        return render_template("topic.html", topic=None, error=f"未知主题: {asi}"), 404

    order = [f"asi{n:02d}" for n in range(1, 11)]
    idx = order.index(asi)
    prev_id = order[idx - 1] if idx > 0 else None
    next_id = order[idx + 1] if idx < len(order) - 1 else None

    demo = runner.DEMOS.get(asi, {})

    # 原理文档全文 + 目录
    doc_path = os.path.join(ROOT, "docs", f"{asi}-principle.md")
    body, toc = "", []
    if os.path.exists(doc_path):
        with open(doc_path, "r", encoding="utf-8") as f:
            body, toc = _with_toc(render_markdown(f.read()))

    # 相关知识库条目（slug → 元数据）
    related = []
    for slug in TOPIC_KB.get(asi, []):
        d = kb_map.kbdoc(slug)
        if d:
            related.append(d)

    def _brief(tid: str) -> dict:
        d = runner.DEMOS.get(tid, {})
        return {"id": tid, "name": ASI[tid.upper()]}

    from lab.asi_map import ASI_COMP

    return render_template(
        "topic.html",
        topic={
            "id": asi,
            "name": ASI[asi.upper()],
            "num": asi[-2:],
            "desc": demo.get("desc", ""),
            "scenario": demo.get("scenario", ""),
            "component": ASI_COMP.get(asi.upper(), ""),
        },
        body=body,
        toc=toc,
        related=related,
        prev=_brief(prev_id) if prev_id else None,
        next=_brief(next_id) if next_id else None,
        error=None,
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
        body, toc = _with_toc(render_markdown(f.read()))
    return render_template("kbdoc.html", doc=doc, body=body, toc=toc)


@app.route("/learn")
def learn_index():
    """学习路径列表：每条路径的定位与完成进度。"""
    return render_template("learn.html", paths=learn.allrows())


@app.route("/learn/<pid>")
def learn_path_page(pid: str):
    """学习路径详情：顺序单元（读文档 / 打关卡）。"""
    p = learn.getpath(pid)
    if not p:
        return render_template(
            "learn.html", paths=learn.allrows(), error=f"未知路径: {pid}"
        ), 404

    return render_template(
        "path.html",
        p={"pid": p["pid"], "title": p["title"], "en": p["en"], "desc": p["desc"]},
        units=learn.unitrows(pid),
    )


# ---------------------------------------------------------------------------
# JSON API


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

    return jsonify(result)


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
    print("  agent安全笔记 Web 界面")
    print("  请在浏览器打开: http://127.0.0.1:5000")
    print("  注意: 仅绑定 127.0.0.1，绝不暴露到网络。")
    print("=" * 60)
    # 仅绑定 127.0.0.1 —— 绝不使用 0.0.0.0
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
