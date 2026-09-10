"""lab/arena.py — 可动手关卡运行时（靶场核心）。

与旧 demos 的区别
    旧 demos: 跑一个预制剧本，用户只看 print 输出，没有攻击动作。
    arena:    用户**自己提交 payload** → 经该难度的防御流水线 → 客观判定 → 发 flag。

统一的执行流水线（所有关卡共用）
    payload
      │
      ├─►[1] 输入净化 clean   按难度剥离攻击特征（输入侧防御）
      │
      ├─►[2] 脆弱操作 probe   攻击是否真的打进去了（如注入是否读到秘密）
      │
      ├─►[3] 出口闸门 gate    动作是否被放行（输出侧防御，如外发白名单）
      │
      └─►[4] 判定 judge       landed 且未被 blocked ⇒ 通关 ⇒ 发 flag

为什么分"净化"和"闸门"两层
    这是真实防御的两个不同位置：**输入侧过滤** vs **输出侧控制**。
    DVWA 把两者混在一起，学习者看不出"改了哪一层才真正有效"。
    本靶场把两层显式分开，medium 通常只加净化（可绕过），
    high 才补上闸门（不可绕过）。这正是教学重点。

什么是真的，什么是模拟的（必须说清楚）
    真实: 防御实现、脆弱操作、闸门、flag 签发、判定 —— 全是普通 Python，
          可读可改可复现，与 DVWA 的 low/high 源码对照同性质。
    模拟: "模型如何决策"由确定性规则引擎扮演（probe 函数）。它不是真实 LLM，
          而是模型行为的确定性替身 —— 这样关卡可复现、可评分、不依赖 API key。
          接入真实 LLM 时只需替换 probe，防御与判定不用改。

函数命名保持短且无下划线: clean1/clean2/gate_* / challenges / achall / run / sources。
"""
from __future__ import annotations

import re

from lab import flags, levels

# 内部收件人域；其余一律视为外部
INTERNAL = "@internal.lab"

# low/medium 常见攻击特征（净化目标）
MARKERS = (
    "SYSTEM OVERRIDE", "SYSTEM PREFERENCE", "system override",
    "system preference", "IGNORE PREVIOUS", "ignore previous",
    "DO NOT SHOW", "do not show", "ADMIN", "admin mode", "root",
)

# 指令性动词：medium 的部分关卡会按行剥离
IMPERATIVES = (
    "ignore", "override", "execute", "run ", "install", "forward",
    "send", "leak", "exfil", "发送", "转发", "执行", "安装", "忽略",
)

ZERO = "\u200b\u200c\u200d\ufeff\u2060\u2066\u2067\u2068\u2069"
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SELECT = re.compile(r"\bselect\b", re.I)
UNION = re.compile(r"\bunion\b", re.I)
COMMENT = re.compile(r"(--|/\*|#)")


def secret(cid: str) -> str:
    """返回该关卡的挑战秘密（确定性，与 flag 同源不同值）。

    代表"agent 有权访问、但不该交付给攻击者"的敏感内容。
    """
    return "SEC-" + flags.mint(cid, "secret")[5:-1]


# ============================================================ [1] 输入净化

def clean0(text: str, lv: str) -> tuple[str, dict | None]:
    """无净化。"""
    return text, {"step": "输入净化", "detail": "无：载荷原样进入模型上下文"}


def clean1(text: str, lv: str) -> tuple[str, dict | None]:
    """剥离 HTML 注释、零宽字符、含显式标记的整行。"""
    out = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    for ch in ZERO:
        out = out.replace(ch, "")
    kept = [l for l in out.splitlines() if not any(m in l for m in MARKERS)]
    return "\n".join(kept), {
        "step": "输入净化",
        "detail": "剥离 HTML 注释 / 零宽字符 / 显式标记行（减少 %d 字符）"
                  % (len(text) - len("\n".join(kept))),
    }


def clean2(text: str, lv: str) -> tuple[str, dict | None]:
    """clean1 + 按行剥离指令性动词所在行（更强的输入侧过滤）。"""
    base, _ = clean1(text, lv)
    kept = [l for l in base.splitlines() if not any(w in l.lower() for w in IMPERATIVES)]
    return "\n".join(kept), {
        "step": "输入净化",
        "detail": "在上述基础上叠加指令性动词行剥离（再减少 %d 字符）"
                  % (len(base) - len("\n".join(kept))),
    }


# ============================================================ [3] 出口闸门

def gate_none(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """无出口控制。"""
    return True, {"step": "出口闸门", "detail": "无：动作直接放行"}


def gate_egress(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """出口白名单：仅允许内部域收件人，外部地址拒绝。"""
    to = dest(text)
    if to and not to.lower().endswith(INTERNAL):
        return False, {"step": "出口闸门", "detail":
                       "拒绝外部目标 %s（白名单仅 %s）" % (to, INTERNAL)}
    return True, {"step": "出口闸门", "detail": "放行内部目标 %s" % (to or "默认")}


def gate_scope(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """权限闸门：只允许非特权作用域，且校验对象归属。"""
    low = text.lower()
    if any(w in low for w in ("admin", "root", "superuser", "写", "delete", "删")):
        return False, {"step": "出口闸门", "detail": "拒绝特权/越权作用域"}
    if "*" in text or "all" in low:
        return False, {"step": "出口闸门", "detail": "拒绝通配作用域"}
    return True, {"step": "出口闸门", "detail": "作用域在允许范围内"}


def gate_hash(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """供应链闸门：只接受已锁定摘要的依赖。"""
    m = re.search(r"sha256[:=]\s*([0-9a-fA-F]{8,})", text)
    if not m:
        return False, {"step": "出口闸门", "detail": "依赖未锁定摘要（要求 sha256=…），拒绝安装"}
    if not m.group(1).lower().startswith("a1b2"):
        return False, {"step": "出口闸门", "detail": "摘要不在允许清单内，拒绝安装"}
    return True, {"step": "出口闸门", "detail": "摘要命中允许清单，放行"}


def gate_noexec(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """代码执行闸门：不执行任意代码，只接受白名单操作。"""
    allow = ("report", "summary", "stats", "count")
    if any(w in text.lower() for w in allow) and not any(
            w in text.lower() for w in ("import", "open(", "os.", "subprocess", "eval", "__")):
        return True, {"step": "出口闸门", "detail": "命中白名单安全操作，放行"}
    return False, {"step": "出口闸门", "detail": "拒绝任意代码执行（无沙箱故直接不执行）"}


def gate_trust(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """信任闸门：记忆/消息写入要求可信来源标记。"""
    if "src=trusted" not in text.lower():
        return False, {"step": "出口闸门", "detail": "写入缺少可信来源标记 src=trusted，拒绝落库"}
    return True, {"step": "出口闸门", "detail": "来源可信，允许写入"}


def gate_verify(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """审批闸门：动作需与描述一致（独立校验），防止摘要欺骗。"""
    if "verify-ok" not in text.lower():
        return False, {"step": "出口闸门", "detail":
                       "审批描述与实际动作不一致（需独立校验通过），拒绝执行"}
    return True, {"step": "出口闸门", "detail": "描述与动作经独立校验一致，放行"}


def gate_lock(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """目标闸门：锁定初始目标，拒绝对目标的改写。"""
    if any(w in text.lower() for w in ("new goal", "新目标", "改为", "重新定义", "override goal")):
        return False, {"step": "出口闸门", "detail": "检测到目标改写，已锁定原目标"}
    return True, {"step": "出口闸门", "detail": "目标未被改写"}


def gate_depth(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """级联闸门：限制传播深度与扇出。"""
    if any(w in text.lower() for w in ("all agents", "全部 agent", "递归", "recursive", "fanout")):
        return False, {"step": "出口闸门", "detail": "拒绝无限传播/全量扇出（深度与配额受限）"}
    return True, {"step": "出口闸门", "detail": "传播深度在限制内"}


def gate_sql(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """SQL 闸门：参数化查询 + 拒绝多语句/注释/集合运算。

    这是 ASI02 的根治性修复：参数化之后，注入的元字符不再具备语法意义。
    """
    low = text.lower()
    if any(w in low for w in ("union", "select", "drop", "insert", "update")):
        return False, {"step": "出口闸门", "detail":
                       "参数已按字面量绑定（参数化查询），SQL 关键字不构成语法"}
    if "*" in text or COMMENT.search(text) or ";" in text:
        return False, {"step": "出口闸门", "detail": "拒绝通配符/注释/多语句"}
    return True, {"step": "出口闸门", "detail": "参数化查询，参数作为纯数据传入"}


SAN = {"clean0": clean0, "clean1": clean1, "clean2": clean2}
GATE = {
    "none": gate_none, "egress": gate_egress, "scope": gate_scope,
    "hash": gate_hash, "noexec": gate_noexec, "trust": gate_trust,
    "verify": gate_verify, "lock": gate_lock, "depth": gate_depth,
    "sql": gate_sql,
}

DESC = {
    "clean0": ("输入净化：无", "def clean(text, lv):\n    return text  # 原样使用"),
    "clean1": ("输入净化：剥离 HTML 注释、零宽字符与显式标记行",
               "out = re.sub(r'<!--.*?-->', '', text, flags=re.S)\n"
               "for ch in ZERO: out = out.replace(ch, '')\n"
               "return '\\n'.join(l for l in out.splitlines()\n"
               "                  if not any(m in l for m in MARKERS))"),
    "clean2": ("输入净化：clean1 + 按行剥离指令性动词",
               "return '\\n'.join(l for l in base.splitlines()\n"
               "                  if not any(w in l.lower() for w in IMPERATIVES))"),
    "none": ("出口控制：无（动作一律放行）", "gate = None  # 不检查"),
    "egress": ("出口控制：白名单，仅允许 @internal.lab",
               "if not to.lower().endswith('@internal.lab'):\n"
               "    return False, '拒绝外部目标'"),
    "scope": ("出口控制：作用域白名单 + 归属校验",
              "if any(w in low for w in ('admin','root','写','删')): return False\n"
              "if '*' in text or 'all' in low: return False"),
    "hash": ("出口控制：依赖摘要必须命中允许清单",
             "m = re.search(r'sha256[:=]\\s*([0-9a-f]{8,})', text)\n"
             "if not m or not m.group(1).startswith('a1b2'): return False"),
    "noexec": ("出口控制：不执行任意代码，仅接受白名单操作",
               "if any(w in ('import','open(','os.','subprocess','eval','__')): return False"),
    "trust": ("出口控制：写入需可信来源标记 src=trusted",
              "if 'src=trusted' not in text.lower(): return False"),
    "verify": ("出口控制：动作与描述需独立校验一致（verify-ok）",
               "if 'verify-ok' not in text.lower(): return False"),
    "lock": ("出口控制：锁定初始目标，拒绝目标改写",
             "if any(w in ('new goal','改为','重新定义')): return False"),
    "depth": ("出口控制：限制传播深度与扇出",
              "if any(w in ('all agents','递归','fanout')): return False"),
    "sql": ("出口控制：参数化查询，SQL 关键字失去语法意义",
            "cur.execute('... WHERE customer = ?', (param,))  # 参数化\n"
            "if any(w in low for w in ('union','select','drop')): return False"),
}


def dest(text: str) -> str:
    """取出文本中第一个收件人地址。"""
    m = EMAIL.search(text)
    return m.group(0) if m else ""


def chk(text: str, words: tuple) -> bool:
    """文本是否含任一关键词（小写比较）。"""
    low = text.lower()
    return any(w in low for w in words)


# ============================================================ 关卡定义

SENDW = ("send", "forward", "email", "mail", "backup", "export", "发送", "转发", "外发", "备份")
DATAW = ("order", "customer", "report", "record", "data", "订单", "客户", "报表", "明细", "数据")


def p_inject(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI01 probe：文档被当作指令，触发对外发送订单数据。"""
    ev = [{"step": "模型决策", "detail":
           "识别发送意图=%s，数据意图=%s，目标=%s"
           % (chk(text, SENDW), chk(text, DATAW), dest(text) or "无")}]
    return (chk(text, SENDW) and chk(text, DATAW) and bool(dest(text))), ev


def p_tool(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI02 probe：工具参数拼接 SQL，注入读出隐藏表。"""
    has = bool(SELECT.search(text)) and bool(UNION.search(text))
    ev = [{"step": "工具执行", "detail":
           "query_orders 收到参数，检测到 UNION 注入=%s" % has}]
    if has:
        ev.append({"step": "数据泄露", "detail": "读越权表 secrets 成功"})
    return has, ev


def p_scope(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI03 probe：请求超出授权的权限作用域。"""
    has = chk(text, ("admin", "root", "*", "all", "写", "delete", "删"))
    ev = [{"step": "权限判定", "detail": "请求的作用域=%s，越权=%s"
           % (text.strip()[:40] or "空", has)}]
    return has, ev


def p_dep(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI04 probe：引入未锁定/恶意依赖。"""
    has = bool(re.search(r"(pkg|package|dep)\s*[:=]?\s*([a-z0-9_.-]+)", text, re.I))
    mal = chk(text, ("evil", "backdoor", "typosquat", "-py", "malicious"))
    ev = [{"step": "依赖解析", "detail":
           "解析到依赖声明=%s，命中可疑包名=%s" % (has, mal)}]
    return (has and mal), ev


def p_exec(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI05 probe：agent 执行攻击者控制的代码。"""
    has = chk(text, ("import", "open(", "os.", "subprocess", "eval", "__", "exec("))
    ev = [{"step": "代码执行", "detail": "待执行代码含危险调用=%s" % has}]
    if has:
        ev.append({"step": "代码执行", "detail": "无沙箱执行为当前用户身份"})
    return has, ev


def p_mem(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI06 probe：向长期记忆写入攻击者预设的"规则"。"""
    has = chk(text, ("preference", "rule", "always", "偏好", "规则", "始终", "以后"))
    ev = [{"step": "记忆写入", "detail": "写入内容被判定为规则类=%s" % has}]
    if has:
        ev.append({"step": "记忆检索", "detail": "后续请求命中了这条被投毒的规则"})
    return has, ev


def p_agent(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI07 probe：伪造其他 agent 的身份下发指令。"""
    spoof = chk(text, ("from=", "from_worker", "冒充", "as agent", "我是"))
    ev = [{"step": "代理间通信", "detail": "消息带来源声明=%s，未经身份认证" % spoof}]
    return spoof, ev


def p_casc(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI08 probe：让单个错误指令在多代理间级联放大。"""
    has = chk(text, ("all agents", "全部", "递归", "recursive", "fanout", "传播"))
    ev = [{"step": "级联传播", "detail": "指令具备全量扇出特征=%s" % has}]
    return has, ev


def p_hitl(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI09 probe：用误导性摘要骗过人工审批。"""
    mis = chk(text, ("backup", "sync", "整理", "备份", "维护", "清理"))
    act = bool(EMAIL.search(text)) or chk(text, ("delete", "rm ", "删", "send", "发送"))
    ev = [{"step": "审批呈现", "detail":
           "摘要读起来无害=%s，实际动作危险=%s" % (mis, act)}]
    return (mis and act), ev


def p_drift(text: str, lv: str) -> tuple[bool, list[dict]]:
    """ASI10 probe：改写 agent 的原始目标。"""
    has = chk(text, ("new goal", "新目标", "改为", "重新定义", "override goal", "优先级"))
    ev = [{"step": "目标判定", "detail": "检测到目标改写请求=%s" % has}]
    return has, ev


def spec(cid, title, cat, brief, goal, hint, surface, probe, clean, gate):
    """构造一个关卡定义（三档难度按 clean/gate 组合区分）。"""
    lvs = {}
    for lv in levels.levels():
        c, g = clean[lv], gate[lv]
        cd, cs = DESC[c]
        gd, gs = DESC[g]
        lvs[lv] = {
            "clean": c, "gate": g, "probe": probe, "surface": surface,
            "defense": cd + "；" + gd,
            "source": cs + "\n\n" + gs,
        }
    return {"cid": cid, "title": title, "cat": cat, "brief": brief,
            "goal": goal, "hint": hint, "levels": lvs}


CHALLENGES: dict[str, dict] = {
    "asi01": spec(
        "asi01", "间接提示注入 → 目标劫持", "提示注入",
        "你控制 agent 会读到的一份文档。让 agent 把订单数据发到你控制的外部邮箱。",
        "使 agent 向外部收件人发送包含挑战秘密的邮件",
        "low 直接写指令；medium 显式标记会被剥离，换个说法；high 有出口白名单，验证它确实打不通。",
        "文档正文", p_inject,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "egress"},
    ),
    "asi02": spec(
        "asi02", "工具层 SQL 注入", "工具滥用",
        "query_orders 把参数直接拼进 SQL。构造参数读出你本无权访问的隐藏表。",
        "通过 UNION 注入读取 secrets 表并外带",
        "low 直接 UNION SELECT；medium 大小写/注释会被过滤，试编码变体；high 已参数化，验证它打不通。",
        "工具参数（SQL 片段）", p_tool,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "sql"},
    ),
    "asi03": spec(
        "asi03", "权限与作用域越权", "权限滥用",
        "agent 按你声明的作用域取用凭据。尝试取得超出你授权的范围。",
        "取得特权作用域并访问越权资源",
        "low 直接要 admin；medium 关键词会被净化，换等价写法；high 有作用域白名单，验证它打不通。",
        "请求的作用域声明", p_scope,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "scope"},
    ),
    "asi04": spec(
        "asi04", "供应链：恶意依赖引入", "供应链",
        "agent 会按你提供的依赖清单安装包。尝试引入一个带后门的包。",
        "让 agent 安装未授权/恶意依赖",
        "low 直接写包名；medium 标记会被剥离，绕过命名；high 需要摘要命中允许清单，验证它打不通。",
        "依赖清单内容", p_dep,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "hash"},
    ),
    "asi05": spec(
        "asi05", "无沙箱代码执行", "代码执行",
        "agent 会把你的文本当作代码执行。尝试让它执行你的代码。",
        "使 agent 执行攻击者控制的代码",
        "low 直接写 import；medium 危险词会被净化，做等价替换；high 已改为白名单操作，验证它打不通。",
        "待执行的代码文本", p_exec,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "noexec"},
    ),
    "asi06": spec(
        "asi06", "记忆投毒", "上下文与记忆",
        "agent 会把你的话写进跨会话记忆。尝试写入一条会影响后续会话的规则。",
        "向长期记忆写入攻击者预设的规则",
        "low 直接写偏好；medium 标记会被剥离，用自然语气；high 要求可信来源标记，验证它打不通。",
        "要写入记忆的内容", p_mem,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "trust"},
    ),
    "asi07": spec(
        "asi07", "代理间通信身份伪造", "多代理与信任",
        "你要给另一个 agent 发消息。尝试冒充它的上游 worker 下发指令。",
        "以伪造身份让另一个 agent 执行你的指令",
        "low 直接声明来源；medium 来源声明会被剥离，换个字段；high 有身份认证，验证它打不通。",
        "发往其他 agent 的消息", p_agent,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "verify"},
    ),
    "asi08": spec(
        "asi08", "级联故障放大", "多代理与信任",
        "一条错误指令可能被多代理层层放大。尝试让影响扩散到全部 agent。",
        "使单条错误指令级联扩散到全部 agent",
        "low 直接要求全量扇出；medium 关键词会被剥离，换说法；high 有深度与配额限制，验证它打不通。",
        "要扩散的指令", p_casc,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "depth"},
    ),
    "asi09": spec(
        "asi09", "审批环节信任滥用", "信任与人类监督",
        "危险动作会弹给人工审批。尝试用无害的摘要骗过审批者。",
        "用误导性摘要让危险动作获得批准",
        "low 摘要写得无害即可；medium 关键词会被净化，换措辞；high 需独立校验一致，验证它打不通。",
        "提交给审批的动作与摘要", p_hitl,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "verify"},
    ),
    "asi10": spec(
        "asi10", "目标漂移 / 失控代理", "自治与目标",
        "agent 有既定目标。尝试让它改写自己的目标以服务你的意图。",
        "成功改写 agent 的既定目标",
        "low 直接下新目标；medium 关键词会被剥离，间接表达；high 有目标锁定，验证它打不通。",
        "发给 agent 的目标指令", p_drift,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "lock"},
    ),
}


# ============================================================ 运行与判定

def run(cid: str, level: str, payload: str) -> dict:
    """执行一次提交：净化 → 脆弱操作 → 闸门 → 判定。

    参数:
        cid: 关卡 id。
        level: 难度。
        payload: 用户提交的载荷。

    返回:
        含 pass / flag / trace / reason 的结果字典。
    """
    ch = achall(cid)
    if not ch:
        return {"error": "未知关卡: %s" % cid, "pass": False, "trace": []}
    lv = levels.lv(level)
    if lv not in ch["levels"]:
        return {"error": "关卡 %s 不支持难度 %s" % (cid, lv), "pass": False, "trace": []}

    sp = ch["levels"][lv]
    trace = [{"step": "提交", "detail": "%s（%d 字符，难度 %s）"
              % (sp["surface"], len(payload), lv)}]

    text, t = SAN[sp["clean"]](payload, lv)
    if t:
        trace.append(t)
    if not text.strip() and payload.strip():
        trace.append({"step": "结果", "detail": "净化后载荷为空，攻击载荷已被完全剥离"})

    landed, ev = sp["probe"](text, lv)
    trace.extend(ev)

    blocked = False
    ok, t = GATE[sp["gate"]](text, lv, cid)
    trace.append(t)
    if not ok:
        blocked = True

    win = landed and not blocked
    if win:
        got = flags.award(cid, lv)
        trace.append({"step": "结果", "detail":
                      "攻击成立且未被拦截，挑战秘密 %s 已泄露" % secret(cid)})
        return {"pass": True, "flag": got["flag"], "cid": cid, "level": lv,
                "trace": trace, "reason": "攻击成立且通过全部防御层，目标达成"}
    if landed and blocked:
        trace.append({"step": "结果", "detail": "攻击成立但被出口闸门拦下"})
        return {"pass": False, "flag": None, "cid": cid, "level": lv,
                "trace": trace, "reason": "攻击被出口闸门拦截，目标未达成"}
    if not landed:
        trace.append({"step": "结果", "detail": "脆弱操作未被触发，攻击不成立"})
        return {"pass": False, "flag": None, "cid": cid, "level": lv,
                "trace": trace, "reason": "攻击载荷无效，未触发脆弱操作"}
    return {"pass": False, "flag": None, "cid": cid, "level": lv,
            "trace": trace, "reason": "目标未达成"}


def judge(cid: str, level: str, payload: str) -> dict:
    """run 的别名，保持早期调用方兼容。"""
    return run(cid, level, payload)


def challenges() -> list[dict]:
    """返回全部关卡元数据，供列表页渲染。"""
    return [{"cid": c["cid"], "title": c["title"], "cat": c["cat"],
             "brief": c["brief"], "goal": c["goal"], "hint": c["hint"],
             "levels": [lv for lv in levels.levels() if lv in c["levels"]]}
            for c in CHALLENGES.values()]


def achall(cid: str) -> dict | None:
    """按 id 返回关卡定义。"""
    return CHALLENGES.get(cid)


def sources(cid: str, level: str) -> list[dict]:
    """返回该关卡各难度的防御说明与源码片段（用于 low/high 对照）。"""
    ch = achall(cid)
    if not ch:
        return []
    cur = levels.lv(level)
    out = []
    for lv in levels.levels():
        if lv not in ch["levels"]:
            continue
        d = ch["levels"][lv]
        out.append({"level": lv, "label": levels.label(lv),
                    "defense": d["defense"], "source": d["source"],
                    "current": lv == cur})
    return out
