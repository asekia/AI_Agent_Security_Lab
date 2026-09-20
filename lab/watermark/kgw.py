"""lab/watermark/kgw.py — 可运行的水印与检测内核（KGW 绿名单）。

本模块是 `docs/kb/mod-watermark.md` 的**执行样本**：文档里讲攻击为什么成立，
这里给出能被测量、能被复现的最小实现。

保真度声明（重要，不要含糊）
    真实: PRF 绿名单（HMAC-SHA256 上下文派生）、gamma/delta 采样偏置、
          z 检验检测器与 p 值公式、唯一性去重计分 —— 与 KGW 方案同构。
    缩放: 词表只有 180 个词，基座是确定性二元马尔可夫模型，不是真的 Transformer。
          因此**绝对数值不能与论文对齐**，只有趋势与相对关系可比较。
    这样做的原因: 关卡要离线、可复现、不依赖 GPU 与 API key。接入真实模型时
    只需要替换 Model.logits 一个方法，水印与检测逻辑不用改。

函数命名保持短且无下划线: logits / gen / detect / green。
"""
from __future__ import annotations

import hashlib
import hmac
import math
import random

# ---------------------------------------------------------------- 词表

WORDS = (
    "the of and to a in that is was it for on as with he be at by this had "
    "not are but from or have an they which one you were her all she there "
    "would their we him been has when who will more no if out so said what "
    "up its about into than them can only other new some could time these "
    "two may then do first any my now such like our over man me even most "
    "made after also did many before must through back years where much your "
    "way well down should because each just those people mr how too little "
    "state good very make world still own see men work long here get both "
    "between life being under never day same another know while last might "
    "us great old year off come since against go came right used take three"
).split()

V = len(WORDS)
IDX = {w: i for i, w in enumerate(WORDS)}

# 常用起始词（让生成的文本看起来像句子）
STARTS = ("the", "a", "in", "it", "we", "they", "this", "one", "many", "most")


# ---------------------------------------------------------------- 基座模型


class Model:
    """确定性二元语言模型：给定前一个 token，返回下一个 token 的 logits。

    这是"模型"的替身。真实接入时替换本类即可，水印逻辑不感知。
    """

    def __init__(self, seed: int = 20260918, temp: float = 1.0):
        self.seed = seed
        self.temp = temp
        rng = random.Random(seed)
        # 每个上下文一行 logits；固定种子 ⇒ 完全可复现
        self.w = [[rng.gauss(0.0, 1.0) for _ in range(V)] for _ in range(V)]
        # 让分布不要太平：加一点词频先验
        self.bias = [0.6 * math.log(1.0 / (i + 3.0)) for i in range(V)]

    def logits(self, ctx: int) -> list[float]:
        """返回上下文 ctx 下的 logits（已含温度与先验）。"""
        row = self.w[ctx]
        b = self.bias
        t = self.temp
        return [(row[i] + b[i]) / t for i in range(V)]


def softmax(xs: list[float]) -> list[float]:
    """数值稳定的 softmax。"""
    m = max(xs)
    es = [math.exp(x - m) for x in xs]
    s = sum(es)
    return [e / s for e in es]


def draw(probs: list[float], rng: random.Random) -> int:
    """按概率分布抽一个 token。"""
    r = rng.random()
    acc = 0.0
    for i, p in enumerate(probs):
        acc += p
        if r <= acc:
            return i
    return len(probs) - 1


# ---------------------------------------------------------------- 密钥与绿名单


def prf(key: bytes, ctx: tuple[int, ...]) -> int:
    """上下文 → 伪随机整数（SelfHash 精神：绿名单由上下文哈希决定）。

    真实 KGW-SelfHash 的 salt 含前一个 token 自身；这里用整段上下文，
    效果等价：绿名单随上下文变化，攻击者不知道 key 就无法预测。
    """
    msg = b",".join(str(c).encode("ascii") for c in ctx)
    return int.from_bytes(hmac.new(key, msg, hashlib.sha256).digest()[:8], "big")


def green(key: bytes, ctx: tuple[int, ...], gamma: float) -> frozenset[int]:
    """返回该上下文下的绿名单 token 集合（大小 floor(gamma * V)）。"""
    k = max(1, int(gamma * V))
    pool = list(range(V))
    random.Random(prf(key, ctx)).shuffle(pool)
    return frozenset(pool[:k])


# ---------------------------------------------------------------- 水印生成


def gen(m: Model, key: bytes, n: int, gamma: float = 0.25,
        delta: float = 2.0, ctxw: int = 1, seed: int = 1,
        prompt: tuple[int, ...] | None = None) -> list[int]:
    """带绿名单偏置的生成。delta=0 即未加水印。

    参数:
        ctxw: 上下文宽度（1 = bigram，2 = trigram，更贴合 SelfHash）。
              **0 = 无上下文依赖**（Kirchenbauer 单表变体 / Zhao 等）：
              绿名单只由 key 决定，任何位置共用同一张表。
              这是一档真实的部署选择，安全性质完全不同（见文档 4.2.5）：
              攻击成本坍缩到 n_query 次，清洗却在每个位置都有效。
        prompt: 起始 token 序列；缺省用固定起点。
    """
    rng = random.Random(seed)
    out = list(prompt) if prompt else [IDX["the"]]
    while len(out) < n:
        ctx = tuple(out[-ctxw:]) if ctxw else ()
        lg = m.logits(ctx[-1]) if ctxw else m.logits(out[-1])
        if delta:
            g = green(key, ctx, gamma)
            for i in g:
                lg[i] += delta
        nxt = draw(softmax(lg), rng)
        out.append(nxt)
    return out


# ---------------------------------------------------------------- 检测器


def detect(ids: list[int], key: bytes, gamma: float = 0.25,
           ctxw: int = 1, ignore_repeat: bool = True) -> dict:
    """绿名单 z 检验。

    统计量: z = (green - gamma*T) / sqrt(gamma*(1-gamma)*T)
    p 值  : 单侧正态近似 p = 0.5 * erfc(z / sqrt(2))

    ctxw=0（单表变体）: 绿名单只由 key 决定，对所有位置计分。
        去重改为按 token 去重（生成侧会重复命中同一绿 token，
        不去重会让重复片段虚增样本量 —— 与 ctxw>=1 的去重哲学一致）。

    ignore_repeat=True 时每个唯一上下文只计一次（对齐官方
    ignore_repeated_ngrams，避免重复片段虚增样本量）。
    """
    seen: set = set()
    g_cnt = 0
    t_cnt = 0
    for i in range(ctxw, len(ids)) if ctxw else range(len(ids)):
        ctx = tuple(ids[i - ctxw:i]) if ctxw else ()
        dkey = ctx if ctxw else ids[i]
        if ignore_repeat:
            if dkey in seen:
                continue
            seen.add(dkey)
        t_cnt += 1
        if ids[i] in green(key, ctx, gamma):
            g_cnt += 1
    if t_cnt == 0:
        return {"z": 0.0, "p": 1.0, "green": 0, "T": 0}
    mu = gamma * t_cnt
    sd = math.sqrt(gamma * (1.0 - gamma) * t_cnt)
    z = (g_cnt - mu) / sd if sd else 0.0
    p = 0.5 * math.erfc(z / math.sqrt(2.0))
    return {"z": z, "p": p, "green": g_cnt, "T": t_cnt}


def text(ids: list[int]) -> str:
    """token id 序列 → 可读文本。"""
    return " ".join(WORDS[i] for i in ids)
