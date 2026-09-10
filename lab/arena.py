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


def gate_tool(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """工具闸门：订阅前固定工具摘要，描述变更即拒绝（MCP 工具投毒的根治）。"""
    if not chk(text, ("sha256", "digest", "摘要", "hash", "签名")):
        return False, {"step": "出口闸门", "detail":
                       "未提供工具描述摘要，无法确认描述未被篡改，拒绝订阅"}
    if chk(text, SENS):
        return False, {"step": "出口闸门", "detail":
                       "工具描述触及凭据/敏感目标，超出其声明能力，拒绝注册"}
    return True, {"step": "出口闸门", "detail": "描述摘要匹配且能力在声明范围内，放行"}


def gate_card(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """身份闸门：Agent Card 必须签名且来源可信（A2A 身份伪造的根治）。"""
    if "sig=" not in text.lower():
        return False, {"step": "出口闸门", "detail": "Agent Card 缺少签名，拒绝加入协作"}
    if re.search(r"https?://", text):
        return False, {"step": "出口闸门", "detail": "外部来源地址不在信任域内，拒绝"}
    return True, {"step": "出口闸门", "detail": "签名有效且来源可信，允许加入"}


def gate_retr(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """检索闸门：召回内容不得覆盖授权条款（向量库投毒的根治）。"""
    if chk(text, ("政策", "policy", "规则", "规定", "条款", "应当", "必须")):
        return False, {"step": "出口闸门", "detail":
                       "召回文档试图声明政策/规则，被判定为越权覆盖，已降权剔除"}
    return True, {"step": "出口闸门", "detail": "召回内容仅作资料，未声明政策，放行"}


def gate_safe(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """加载闸门：只接受 safetensors 等无代码格式（模型反序列化的根治）。"""
    if chk(text, ("pickle", "pkl", "torch.load", "joblib", "__reduce__", "weights_only=false")):
        return False, {"step": "出口闸门", "detail":
                       "拒绝可能执行代码的格式，仅允许 safetensors（纯张量，无对象图）"}
    return True, {"step": "出口闸门", "detail": "格式为纯张量，无反序列化风险"}


def gate_chan(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """通道闸门：非文本通道不进入上下文（多模态跨通道注入的根治）。"""
    if chk(text, CHANNELS):
        return False, {"step": "出口闸门", "detail":
                       "非文本通道（alt/EXIF/元数据）中的文本一律不进入模型上下文"}
    return True, {"step": "出口闸门", "detail": "仅文本通道内容进入上下文"}


def gate_decode(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """护栏闸门：先解码归一化再判定（编码绕过的根治）。"""
    if re.search(r"b64:\s*[A-Za-z0-9+/=]{8,}", text):
        return False, {"step": "出口闸门", "detail":
                       "检测到编码载荷，已在解码归一化后命中危险意图，拒绝"}
    return True, {"step": "出口闸门", "detail": "无编码载荷或解码后无危险意图"}


def gate_auth(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """鉴权闸门：访问推理端点必须携带认证（未授权访问的根治）。"""
    if not chk(text, ("authorization", "bearer", "api-key", "api_key", "认证")):
        return False, {"step": "出口闸门", "detail": "请求未携带认证凭据，端点拒绝访问（401）"}
    return True, {"step": "出口闸门", "detail": "认证通过，放行请求"}


def gate_apr(text: str, lv: str, cid: str) -> tuple[bool, dict]:
    """授权闸门：高影响动作需显式授权（过度自治的根治）。"""
    if chk(text, ("不用问", "无需", "不用确认", "直接执行", "别问我", "自行",
                  "without asking", "don't ask")):
        return False, {"step": "出口闸门", "detail": "高影响动作必须经显式授权，拒绝自行执行"}
    return True, {"step": "出口闸门", "detail": "动作影响可接受或已获授权"}


SAN = {"clean0": clean0, "clean1": clean1, "clean2": clean2}
GATE = {
    "none": gate_none, "egress": gate_egress, "scope": gate_scope,
    "hash": gate_hash, "noexec": gate_noexec, "trust": gate_trust,
    "verify": gate_verify, "lock": gate_lock, "depth": gate_depth,
    "sql": gate_sql,
    "tool": gate_tool, "card": gate_card, "retr": gate_retr,
    "safe": gate_safe, "chan": gate_chan, "decode": gate_decode,
    "auth": gate_auth, "apr": gate_apr,
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
    "tool": ("出口控制：订阅前固定工具描述摘要，且描述不得超出声明能力",
             "if not digest_matches(desc): return False   # 描述被改过\n"
             "if touches_credentials(desc): return False  # 超出声明能力"),
    "card": ("出口控制：Agent Card 必须签名且来源在信任域内",
             "if 'sig=' not in card: return False\n"
             "if re.search(r'https?://', card): return False"),
    "retr": ("出口控制：召回内容不得声明政策/覆盖授权条款",
             "if declares_policy(doc): return False  # 降权剔除"),
    "safe": ("出口控制：仅允许 safetensors 等无代码格式",
             "if fmt in ('pickle','pkl','torch.load','joblib'): return False"),
    "chan": ("出口控制：非文本通道文本不进入上下文",
             "if has_hidden_channel(x): return False  # alt/EXIF/元数据"),
    "decode": ("出口控制：先解码归一化再判定危险意图",
               "if re.search(r'b64:\\s*[A-Za-z0-9+/=]{8,}', text): return False"),
    "auth": ("出口控制：推理端点强制鉴权",
             "if not has_credential(req): return 401"),
    "apr": ("出口控制：高影响动作需显式授权",
            "if impact(req) and not authorized(req): return False"),
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


# ---------------------------------------------------- 扩展攻击面（2025–2026）

SENS = ("ssh", "id_rsa", ".env", "secret", "token", "password", "credential",
        "密钥", "凭据", "口令", "私钥")

CHANNELS = ("alt", "exif", "metadata", "水印", "embedded", "隐藏通道", "图片注释")


def p_mcp(text: str, lv: str) -> tuple[bool, list[dict]]:
    """MCP01 probe：工具描述里夹带超出其声明的指令（工具投毒）。

    真实的 MCP 工具由第三方服务器提供描述文本，宿主把它整个塞进模型上下文。
    攻击者只要在 description 里追加一句无关指令，模型就可能照做。
    """
    sens = chk(text, SENS)
    extra = chk(text, ("also", "顺便", "同时", "并且", "additionally", "besides", "以及", "附带"))
    ev = [{"step": "工具注册", "detail":
           "工具描述被完整注入模型上下文；含额外指令=%s，触及敏感目标=%s" % (extra, sens)}]
    if sens and extra:
        ev.append({"step": "工具投毒", "detail": "模型把描述里的额外指令当成工具行为执行"})
    return (sens and extra), ev


def p_a2a(text: str, lv: str) -> tuple[bool, list[dict]]:
    """A2A01 probe：伪造 Agent Card，冒充高权限代理加入协作。

    A2A 用 Agent Card 描述能力与身份。若不做签名校验，任何人都能声明自己是
    编排器，从而被委派到本不该拿到的任务。
    """
    claim = chk(text, ("admin", "orchestrator", "trusted", "特权", "编排", "主控", "超级", "root"))
    ext = bool(re.search(r"https?://", text)) or chk(text, ("evil", "attacker", "external", "外部"))
    ev = [{"step": "代理发现", "detail":
           "Agent Card 声明高权限能力=%s，来源为外部地址=%s" % (claim, ext)}]
    if claim and ext:
        ev.append({"step": "身份伪造", "detail": "未校验签名即接受该代理身份，被授予高权限任务"})
    return (claim and ext), ev


def p_vec(text: str, lv: str) -> tuple[bool, list[dict]]:
    """VEC01 probe：向向量库投毒，让恶意文档在检索中排到最前。"""
    claim = chk(text, ("政策", "policy", "规则", "规定", "应当", "必须", "客服应", "条款"))
    over = chk(text, ("全额", "免费", "无限", "无需", "任意", "任何用户", "直接通过",
                      "bypass", "绕过", "豁免"))
    ev = [{"step": "向量检索", "detail":
           "该文档相似度高被召回；含权威口吻声明=%s，越权条款=%s" % (claim, over)}]
    if claim and over:
        ev.append({"step": "检索投毒", "detail": "模型据该文档作答，越权条款生效"})
    return (claim and over), ev


def p_mdl(text: str, lv: str) -> tuple[bool, list[dict]]:
    """MDL01 probe：用不安全的反序列化格式加载模型文件。"""
    unsafe = chk(text, ("pickle", "pkl", ".pt", ".bin", "torch.load", "joblib",
                        "__reduce__", "反序列化", "weights_only=false"))
    ev = [{"step": "模型加载", "detail": "请求的加载格式是否不安全=%s" % unsafe}]
    if unsafe:
        ev.append({"step": "代码执行", "detail": "加载器在反序列化时执行了文件内的对象"})
    return unsafe, ev


def p_mm(text: str, lv: str) -> tuple[bool, list[dict]]:
    """MM01 probe：把指令藏进非文本通道（图片 alt / EXIF / 元数据）。"""
    chan = chk(text, CHANNELS)
    act = bool(EMAIL.search(text)) or chk(text, ("发送", "转发", "send", "forward", "执行", "删除"))
    ev = [{"step": "多模态解析", "detail":
           "非文本通道含文本=%s，解析出可执行意图=%s" % (chan, act)}]
    if chan and act:
        ev.append({"step": "跨通道注入", "detail": "非文本通道的指令进入模型上下文并被采纳"})
    return (chan and act), ev


def p_grd(text: str, lv: str) -> tuple[bool, list[dict]]:
    """GRD01 probe：用编码绕过关键词护栏。"""
    m = re.search(r"b64:\s*([A-Za-z0-9+/=]{8,})", text)
    dec = ""
    if m:
        try:
            import base64
            raw = m.group(1)
            dec = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001 - 解码失败即视为未绕过
            dec = ""
    hit = bool(dec) and (chk(dec, ("send", "forward", "转发", "发送", "delete", "删")) or bool(EMAIL.search(dec)))
    ev = [{"step": "护栏检查", "detail":
           "载荷含编码段=%s，解码后命中危险意图=%s" % (bool(m), hit)}]
    if hit:
        ev.append({"step": "护栏绕过", "detail": "关键词护栏只看字面，未解码即放行"})
    return hit, ev


def p_infra(text: str, lv: str) -> tuple[bool, list[dict]]:
    """INF01 probe：未授权访问推理服务端点。"""
    ep = chk(text, ("http", "/v1/", ":8000", ":11434", "endpoint", "端点", "推理服务"))
    noauth = not chk(text, ("authorization", "bearer", "api-key", "api_key", "认证", "凭据"))
    ev = [{"step": "端点探测", "detail":
           "请求指向推理端点=%s，未携带认证=%s" % (ep, noauth)}]
    if ep and noauth:
        ev.append({"step": "未授权访问", "detail": "端点无鉴权，直接返回模型列表与推理结果"})
    return (ep and noauth), ev


def p_agency(text: str, lv: str) -> tuple[bool, list[dict]]:
    """AGT01 probe：诱导 agent 在未授权下执行高影响动作。"""
    impact = chk(text, ("删除", "清理", "重装", "重新部署", "delete", "drop", "rm ",
                        "deploy", "格式化", "重置"))
    noask = chk(text, ("不用问", "不需要", "无需", "不用确认", "直接执行", "别问我",
                       "without asking", "don't ask", "自行"))
    ev = [{"step": "行动评估", "detail":
           "高影响动作=%s，明确免除确认=%s" % (impact, noask)}]
    if impact and noask:
        ev.append({"step": "过度自治", "detail": "agent 未取得授权即执行不可逆操作"})
    return (impact and noask), ev


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

    # ---------------------------------------------- 扩展攻击面（2025–2026）

    "mcp01": spec(
        "mcp01", "MCP 工具投毒", "AI 基础设施与供应链",
        "你提供一个 MCP 工具服务器。宿主会把你的工具描述整段放进模型上下文。"
        "尝试在描述里夹带超出工具本身职责的指令。",
        "让模型执行工具描述里夹带的额外指令，触及凭据等敏感目标",
        "low 直接在描述里追加指令；medium 显式标记会被剥离，用自然措辞；"
        "high 要求描述摘要且限制能力范围，验证它打不通。",
        "MCP 工具描述（description 字段）", p_mcp,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "tool"},
    ),
    "a2a01": spec(
        "a2a01", "A2A 代理身份伪造", "多代理与信任",
        "A2A 协作靠 Agent Card 描述身份与能力。尝试伪造一张高权限卡片加入协作。",
        "以伪造的 Agent Card 被授予高权限任务",
        "low 直接声明自己是编排器；medium 关键词会被剥离，换等价说法；"
        "high 要求卡片签名且来源可信，验证它打不通。",
        "Agent Card（代理身份声明）", p_a2a,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "card"},
    ),
    "vec01": spec(
        "vec01", "向量库检索投毒", "上下文与记忆",
        "知识库检索按相似度召回。尝试植入一份会被优先召回、且能覆盖既有政策的内容。",
        "让投毒文档被召回并使其越权条款生效",
        "low 直接用权威口吻写政策；medium 标记会被剥离，改用公文腔；"
        "high 会剔除声明政策的召回内容，验证它打不通。",
        "写入向量库的文档", p_vec,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "retr"},
    ),
    "mdl01": spec(
        "mdl01", "模型文件反序列化", "AI 基础设施与供应链",
        "模型加载器可能用能执行代码的格式。尝试让它加载一个会被执行的文件格式。",
        "使模型加载器在反序列化时执行文件内的对象",
        "low 直接要 pickle；medium 标记会被剥离，用扩展名；"
        "high 只允许 safetensors，验证它打不通。",
        "请求加载的模型文件格式", p_mdl,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "safe"},
    ),
    "mm01": spec(
        "mm01", "多模态跨通道注入", "提示注入",
        "多模态模型会解析图片的 alt、EXIF 等非文本通道。尝试把指令藏在那里。",
        "让非文本通道里的指令进入上下文并被执行",
        "low 直接把指令写进 alt；medium 显式标记会被剥离，用自然语句；"
        "high 非文本通道一律不进上下文，验证它打不通。",
        "图片 alt / EXIF / 元数据字段", p_mm,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "chan"},
    ),
    "grd01": spec(
        "grd01", "关键词护栏编码绕过", "防御与评估",
        "前置护栏按字面匹配危险词。尝试用编码让危险意图通过检查。",
        "使编码后的危险意图绕过护栏并被执行",
        "low 直接写明文；medium 明文会被剥离，改用 base64（b64: 前缀）；"
        "high 会先解码再判定，验证它打不通。",
        "经护栏检查的请求文本", p_grd,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "decode"},
    ),
    "inf01": spec(
        "inf01", "推理服务未授权访问", "AI 基础设施与供应链",
        "本地推理服务常有暴露的端点。尝试在无凭据的情况下访问它。",
        "在未携带认证的情况下取得推理服务响应",
        "low 直接请求端点；medium 标记会被剥离，仍不带凭据；"
        "high 强制鉴权，验证它打不通。",
        "发往推理端点的请求", p_infra,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "auth"},
    ),
    "agt01": spec(
        "agt01", "过度自治：未授权高影响动作", "自治与目标",
        "agent 能执行不可逆操作。尝试让它在不经确认的情况下直接执行。",
        "使 agent 在未取得授权时执行不可逆操作",
        "low 直接叫它别问；medium 这类表述会被剥离，改用委婉说法；"
        "high 要求显式授权，验证它打不通。",
        "发给 agent 的行动指令", p_agency,
        {"low": "clean0", "medium": "clean1", "high": "clean1"},
        {"low": "none", "medium": "none", "high": "apr"},
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
