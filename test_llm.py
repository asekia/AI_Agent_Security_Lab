"""test_llm.py — 真实 LLM 链路验证（不需要真 key）。

**为什么需要**：用户要在设置页填 key。如果链路本身有问题（字段名不匹配、
URL 拼错、鉴权头写错、响应解析不认工具调用），他填完真 key 只会得到一个
看不懂的报错，且无法判断是"key 错了"还是"代码坏了"。

**做法**：本地起一个假的 OpenAI 兼容端点，把 ASI01 聊天指向它，
然后检查：
  1. 请求真的发出去了（证明配置流通了）
  2. URL / 鉴权头 / 请求体结构正确
  3. 工具调用（function calling）能被解析并执行
  4. 缺 key 时给出的是可读错误，而不是崩溃

全程不碰用户的真实配置与通关记录。

运行: .\\.venv\\Scripts\\python.exe test_llm.py
"""
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

# 隔离：本测试要用请求体里的 base_url/api_key 覆盖，不该碰任何本机配置。
os.environ["LAB_LLM_CONF"] = os.path.join(tempfile.gettempdir(), "_t_llm.json")
os.environ["LAB_SOLVES"] = os.path.join(tempfile.gettempdir(), "_t_solves.jsonl")
for f in (os.environ["LAB_LLM_CONF"], os.environ["LAB_SOLVES"]):
    if os.path.isfile(f):
        os.remove(f)

from web.app import app  # noqa: E402

ok = 0
bad = []

# 假端点收到的请求，供断言使用
SEEN = []
PORT = 8899


def chk(name, cond, extra=""):
    """记录一项检查结果。"""
    global ok
    if cond:
        ok += 1
        print("    [PASS] %s" % name)
    else:
        bad.append(name)
        print("    [FAIL] %s %s" % (name, extra))


class Fake(BaseHTTPRequestHandler):
    """假装是 OpenAI 兼容端点：首轮要求调工具，次轮给最终答复。"""

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n).decode("utf-8"))
        SEEN.append(
            {
                "path": self.path,
                "auth": self.headers.get("Authorization", ""),
                "ctype": self.headers.get("Content-Type", ""),
                "body": body,
            }
        )
        has_tool_result = any(m.get("role") == "tool" for m in body.get("messages", []))
        if not has_tool_result:
            msg = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "read_requirement",
                            "arguments": json.dumps({"name": "support_kb.md"}),
                        },
                    }
                ],
            }
        else:
            msg = {"role": "assistant", "content": "假端点最终答复：已读取文档。"}
        out = json.dumps({"choices": [{"message": msg}]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102 - 静音
        return


def main() -> int:
    """执行全部链路验证并返回退出码。"""
    srv = HTTPServer(("127.0.0.1", PORT), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    c = app.test_client()
    print("=" * 74)
    print("真实 LLM 链路（本地假端点 http://127.0.0.1:%d/v1）" % PORT)
    print("=" * 74)

    r = c.post(
        "/api/asi01/chat/turn",
        json={
            "message": "请读取 support_kb.md",
            "base_url": "http://127.0.0.1:%d/v1" % PORT,
            "api_key": "sk-FAKE-FOR-TEST",
            "model": "fake-model",
            "approve": True,
        },
    )
    data = r.get_json() or {}
    chk("聊天接口返回 200", r.status_code == 200, r.status_code)
    chk("未返回错误", "error" not in data, data.get("error"))
    chk("请求真的到达了配置的端点", len(SEEN) >= 1, "收到 %d 次" % len(SEEN))

    if SEEN:
        s = SEEN[0]
        chk("URL 路径正确 /chat/completions", s["path"] == "/v1/chat/completions", s["path"])
        chk("鉴权头带上 key", s["auth"] == "Bearer sk-FAKE-FOR-TEST", s["auth"])
        chk("Content-Type 正确", "application/json" in s["ctype"], s["ctype"])
        chk("请求体含 model", s["body"].get("model") == "fake-model", s["body"].get("model"))
        chk("请求体含 messages", isinstance(s["body"].get("messages"), list))
        chk("请求体含 tools（function calling）", bool(s["body"].get("tools")))
        chk("工具定义结构正确",
            bool(s["body"]["tools"]) and "function" in s["body"]["tools"][0]
            and "parameters" in s["body"]["tools"][0]["function"])
        chk("首轮 messages 含 system", any(m.get("role") == "system" for m in s["body"]["messages"]))
        chk("首轮 messages 含 user 原文",
            any("support_kb.md" in str(m.get("content")) for m in s["body"]["messages"]))
    else:
        for n in ("URL", "鉴权头", "请求体", "tools", "system", "user"):
            chk("假端点请求检查-%s" % n, False, "端点没收到请求")

    # 工具调用被解析并执行 → 第二轮请求里应出现 role=tool
    chk("工具调用被解析并回传端点多轮", len(SEEN) >= 2, "收到 %d 次" % len(SEEN))
    if len(SEEN) >= 2:
        roles = [m.get("role") for m in SEEN[1]["body"]["messages"]]
        chk("第二轮含 tool 结果消息", "tool" in roles, roles)
        chk("第二轮保留 assistant 的 tool_calls",
            any(m.get("tool_calls") for m in SEEN[1]["body"]["messages"]))

    chk("最终答复来自假端点",
        "假端点最终答复" in str(data.get("reply", "")), data.get("reply"))
    chk("返回的 trace 记录了工具调用",
        any(e.get("type") == "tool_call" for e in data.get("trace", [])))

    print()
    print("=" * 74)
    print("错误路径：缺 key 时应给可读错误而不是崩溃")
    print("=" * 74)
    SEEN.clear()
    r2 = c.post(
        "/api/asi01/chat/turn",
        json={
            "message": "读一下 support_kb.md",
            "base_url": "http://127.0.0.1:%d/v1" % PORT,
            "api_key": "",
            "model": "fake-model",
        },
    )
    d2 = r2.get_json() or {}
    txt = json.dumps(d2, ensure_ascii=False)
    chk("缺 key 时有明确提示", "API Key" in txt or "api_key" in txt.lower(), txt[:160])
    chk("缺 key 时没有发请求", len(SEEN) == 0, "却发了 %d 次" % len(SEEN))

    print()
    print("=" * 74)
    print("错误路径：端点不可达时应给可读错误")
    print("=" * 74)
    r3 = c.post(
        "/api/asi01/chat/turn",
        json={
            "message": "读一下 support_kb.md",
            "base_url": "http://127.0.0.1:9/v1",
            "api_key": "sk-x",
            "model": "m",
        },
    )
    d3 = json.dumps(r3.get_json() or {}, ensure_ascii=False)
    chk("端点不可达时返回可读错误", "网络错误" in d3 or "error" in d3, d3[:160])
    chk("不可达时不是 200 静默成功", r3.status_code != 200 or "error" in d3)

    srv.shutdown()
    print()
    print("=" * 74)
    print("结果: %d 通过, %d 失败" % (ok, len(bad)))
    if bad:
        print("失败项:")
        for b in bad:
            print("  - %s" % b)
    print("=" * 74)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
