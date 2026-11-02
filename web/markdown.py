"""web/markdown.py — 极简安全的 Markdown 渲染器（仅用于知识库文档页）。

只支持本文档用到的子集：标题 / 表格 / 无序与有序列表 / 代码块 /
引用块 / 段落 / 加粗 / 行内代码 / 链接。其余一律按纯文本 HTML 转义输出，
避免引入任何不可信 HTML。
"""
from __future__ import annotations

import html
import re

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BARE_URL_RE = re.compile(r"(?<![\(\"'])(https?://[^\s)<>]+)")
_HEAD_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_UL_RE = re.compile(r"^\s*[-*]\s+(.*)$")
_OL_RE = re.compile(r"^\s*\d+\.\s+(.*)$")
_BQ_RE = re.compile(r"^\s*>\s?(.*)$")


def _inline(text: str) -> str:
    """行内渲染：转义后处理链接/行内代码/加粗。"""
    text = html.escape(text)
    text = _LINK_RE.sub(r'<a href="\2" target="_blank" rel="noopener">\1</a>', text)
    text = _BARE_URL_RE.sub(
        r'<a href="\1" target="_blank" rel="noopener">\1</a>', text
    )
    text = _CODE_RE.sub(r"<code>\1</code>", text)
    text = _BOLD_RE.sub(r"<strong>\1</strong>", text)
    return text


def render_markdown(text: str) -> str:
    """把 Markdown 文本渲染为安全的 HTML 片段。"""
    lines = text.splitlines()
    out: list[str] = []
    para: list[str] = []
    table: list[str] = []
    list_buf: list[str] = []
    list_kind: str | None = None  # "ul" | "ol"
    in_code = False
    code_buf: list[str] = []

    def flush_para() -> None:
        if para:
            out.append("<p>" + _inline(" ".join(para)) + "</p>")
            para.clear()

    def flush_list() -> None:
        nonlocal list_kind
        if not list_buf:
            return
        tag = "ol" if list_kind == "ol" else "ul"
        out.append(f"<{tag}>")
        for item in list_buf:
            out.append(f"<li>{_inline(item)}</li>")
        out.append(f"</{tag}>")
        list_buf.clear()
        list_kind = None

    def flush_table() -> None:
        if not table:
            return
        rows = [r for r in table if r.strip() and not re.match(r"^\s*\|?[\s:\-|]+\|?\s*$", r)]
        out.append('<table class="asi-table">')
        for i, row in enumerate(rows):
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            tag = "th" if i == 0 else "td"
            out.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
        out.append("</table>")
        table.clear()

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        # 代码围栏
        if stripped.startswith("```"):
            flush_para(); flush_list(); flush_table()
            if in_code:
                out.append("<pre>" + html.escape("\n".join(code_buf)) + "</pre>")
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue

        if not stripped:
            flush_para(); flush_list(); flush_table()
            continue

        m = _HEAD_RE.match(stripped)
        if m:
            flush_para(); flush_list(); flush_table()
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
            continue

        m = _UL_RE.match(stripped)
        if m:
            flush_para(); flush_table()
            if list_kind != "ul":
                flush_list()
                list_kind = "ul"
            list_buf.append(m.group(1))
            continue

        m = _OL_RE.match(stripped)
        if m:
            flush_para(); flush_table()
            if list_kind != "ol":
                flush_list()
                list_kind = "ol"
            list_buf.append(m.group(1))
            continue

        m = _BQ_RE.match(stripped)
        if m:
            flush_para(); flush_list(); flush_table()
            out.append("<blockquote>" + _inline(m.group(1)) + "</blockquote>")
            continue

        if stripped.startswith("|"):
            flush_para(); flush_list()
            table.append(line)
            continue

        flush_list(); flush_table()
        para.append(stripped)

    flush_para(); flush_list(); flush_table()
    if in_code:
        out.append("<pre>" + html.escape("\n".join(code_buf)) + "</pre>")
    return "\n".join(out)
