"""test_web.py — Web 层页面可达性与内容契约验证。

验证用户真正接触的那一层：每个页面能打开、关键内容在页面上、
侧栏与标题不含已删除功能的引用。

**测试隔离**：本文件把 LLM 配置重定向到临时文件，
测试不得读写用户的本机配置。

运行:
    .\.venv\Scripts\python.exe test_web.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

_TMPC = tempfile.NamedTemporaryFile(prefix="lab_conf_test_", suffix=".json",
                                    delete=False)
_TMPC.close()
os.environ["LAB_LLM_CONF"] = _TMPC.name

from web.app import app  # noqa: E402

ok = 0
bad = []
c = app.test_client()


def chk(name, cond, extra=""):
    """记录一项检查结果。"""
    global ok
    if cond:
        ok += 1
        print("    [PASS] %s" % name)
    else:
        bad.append(name)
        print("    [FAIL] %s %s" % (name, extra))


def get(page):
    """GET 一个页面，返回 (状态码, 文本)。"""
    r = c.get(page)
    return r.status_code, r.data.decode("utf-8")


def main() -> int:
    """执行 Web 层全部验证并返回退出码。"""
    print("=" * 74)
    print("核心页面可达性")
    print("=" * 74)
    for page, must in [
        ("/", ["agent安全笔记", "ASI 主题", "学习路径"]),
        ("/learn", ["学习路径", "P1", "P2", "P3"]),
        ("/learn/p1", ["上下文窗口溢出", "打开文档"]),
        ("/learn/p2", ["多文档拆分注入"]),
        ("/learn/p3", ["MLOps 平台攻击面"]),
        ("/topic/asi01", ["系统提示", "本页内容", "相关知识库"]),
        ("/topic/asi05", ["意外代码执行"]),
        ("/asi/asi01", ["运行 asi01"]),
    ]:
        code, s = get(page)
        chk("%s 200" % page, code == 200)
        for m in must:
            chk("%s 含「%s」" % (page, m), m in s)

    print()
    print("=" * 74)
    print("知识库文档全部可达")
    print("=" * 74)
    from lab.kb_map import KB_DOCS
    miss = [slug for slug in KB_DOCS if c.get("/kb/" + slug).status_code != 200]
    chk("全部 %d 篇 200" % len(KB_DOCS), not miss, str(miss[:5]))

    print()
    print("=" * 74)
    print("已删除功能不得有残留入口")
    print("=" * 74)
    _, home = get("/")
    chk("侧栏无工具组", 'side-group">工具' not in home)
    chk("无 /arena 链接", "/arena" not in home)
    chk("无 /watermark 链接", "/watermark" not in home)
    chk("无 /playground 链接", "/playground" not in home)
    chk("无 /selfaudit 链接", "/selfaudit" not in home)
    chk("无 /agent 链接", "/agent" not in home)
    chk("无通关 flag 字样", "flag{" not in home)
    for dead in ("/arena", "/arena/asi01/low", "/watermark", "/playground",
                 "/selfaudit", "/agent", "/asi01/chat", "/trace", "/log",
                 "/settings", "/kb/case-prompt", "/kb/mod-watermark"):
        chk("%s 404" % dead, c.get(dead).status_code == 404)

    print()
    print("=" * 74)
    print("结果: %d 通过, %d 失败" % (ok, len(bad)))
    print("=" * 74)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
