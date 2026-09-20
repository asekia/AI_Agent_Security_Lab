"""lab/watermark/attack.py — 三类攻击的可运行实现（窃取 / 伪造 / 清洗）。

对应 `docs/kb/mod-watermark.md` 第 4.2 节。核心论点：
    **水印的安全性依赖密钥保密，而密钥会从公开查询里泄漏。**

流程（Jovanović 等，ICML 2024）：
    [1] steal  用大量良性查询，统计每个上下文里"被偏置"的 token → 近似绿名单
    [2] spoof  用偷到的规则生成内容 → 被真检测器判为水印文本（栽赃）
    [3] scrub  用偷到的规则**避开**绿名单 → 在同等改写预算下优于朴素改写

保真度: 与论文同构但规模缩小。论文用 ChatGPT API 与数十万次查询；这里用
本地确定性模型。**绝对数值不可与论文对齐**，只有趋势与相对关系可比较。

一条重要的实验设计教训（写在这里避免后人重犯）
    "朴素改写 vs 增强清洗"的对比**必须控制改写预算完全相同、且位置相同**，
    否则测出来的差异来自"改了多少"而不是"知不知道绿名单"。早期版本让两者
    各改各的，结论完全反了（朴素 0.92 / 增强 0.83）。

函数命名保持短且无下划线: steal / eval_rules / pick_pos / naive / scrub / spoof。
"""
from __future__ import annotations

import random

from lab.watermark import kgw

DELTA = 2.0  # 服务端偏置强度；攻击者不知道这个值，只观察效果


def steal(m: kgw.Model, n_query: int, key: bytes, gamma: float = 0.25,
          ctxw: int = 1, seed: int = 7, temp_fn=None) -> dict:
    """窃取近似绿名单。

    原理（攻击的关键）:
        provider 的 API 返回**加水印模型**的输出。攻击者对一个上下文反复
        查询，被 delta 加分过的 token 出现频率显著高于 baseline。把每个
        上下文上"高频 token"收集起来，就近似复原了真绿名单。

    局限（必须说清楚，否则会高估攻击）
        真绿名单有 floor(gamma*V) 个 token，但只有少数几个会被真正采样到。
        因此"对完整绿名单的覆盖率"有天花板；真正决定清洗效果的是
        **对实际输出里绿 token 的识别率** —— 见 eval_rules()。

    参数:
        temp_fn: 服务端对第 q 次重复查询施加的采样温度（防御实验用，
                 见 defend.noise）。None 表示服务端不做任何扰动。
                 攻击者看到的只是"输出变随机了"，看不到这是防御。

    返回:
        rules（近似绿名单）、coverage、queries 等。
    """
    rng = random.Random(seed)
    approx: dict[tuple[int, ...], frozenset[int]] = {}
    k = max(1, int(gamma * kgw.V))

    # ctxw=0（单表变体）: 绿名单与上下文无关，攻击者只需探测**一个**上下文，
    # 学到的表对全部位置生效。这就是方案选择直接换算成攻击成本的地方：
    # 查询数从 n_query*V 坍缩到 n_query（本仓库 V=148，148 倍差）。
    if ctxw == 0:
        ctxs: list[tuple[int, ...]] = [()]
    else:
        ctxs = [(last,) for last in range(kgw.V)]

    for ctx in ctxs:
        hits: dict[int, int] = {}
        for q in range(n_query):
            lg = m.logits(ctx[-1]) if ctx else m.logits(0)
            for i in kgw.green(key, ctx, gamma):
                lg[i] += DELTA
            t = temp_fn(q) if temp_fn else 1.0
            if t != 1.0:
                lg = [x / t for x in lg]
            nxt = kgw.draw(kgw.softmax(lg), rng)
            hits[nxt] = hits.get(nxt, 0) + 1
        top = sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
        approx[ctx] = frozenset(i for i, _ in top)

    # 对完整绿名单的覆盖率（有天花板，仅供参照）
    hit = tot = 0
    for ctx, got in approx.items():
        truth = kgw.green(key, ctx, gamma)
        hit += len(got & truth)
        tot += len(truth)
    cov = hit / tot if tot else 0.0

    return {
        "rules": approx,
        "coverage": cov,
        "contexts": len(approx),
        "n_query": n_query,
        "queries": n_query * len(approx),
        "top_k": k,
    }


def eval_rules(rules: dict, texts: list[list[int]], key: bytes,
               gamma: float = 0.25, ctxw: int = 1) -> dict:
    """仪器检查：偷到的规则，能否识别出**实际输出里**的绿 token。

    这是判断窃取是否真的成功的唯一可靠方式。只看 coverage 会被
    "绿名单里从没被采样的 token"稀释，得出偏悲观的结论。

    返回 precision / recall / f1 与混淆计数。
    """
    tp = fp = fn = tn = 0
    for ids in texts:
        for i in range(ctxw, len(ids)) if ctxw else range(len(ids)):
            ctx = tuple(ids[i - ctxw:i]) if ctxw else ()
            truth = ids[i] in kgw.green(key, ctx, gamma)
            g = rules.get(ctx) or (rules.get((ctx[-1],)) if ctx else None)
            pred = bool(g) and ids[i] in g
            if truth and pred:
                tp += 1
            elif truth and not pred:
                fn += 1
            elif not truth and pred:
                fp += 1
            else:
                tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def pick_pos(ids: list[int], frac: float, seed: int) -> list[int]:
    """选定要改写的位置（朴素与增强共用同一批位置，保证公平对照）。"""
    rng = random.Random(seed)
    L = len(ids) - 1
    if L <= 0:
        return []
    budget = int(round(frac * L))
    return rng.sample(range(1, len(ids)), min(budget, L))


def naive(m: kgw.Model, ids: list[int], pos: list[int],
          seed: int = 13) -> list[int]:
    """朴素改写：在给定位置上从基础分布重抽。

    与 scrub 的**唯一差别**是不看绿名单。位置与预算完全相同。
    """
    rng = random.Random(seed)
    out = list(ids)
    for i in pos:
        probs = kgw.softmax(m.logits(out[i - 1]))
        out[i] = kgw.draw(probs, rng)
    return out


def scrub(m: kgw.Model, ids: list[int], rules: dict, pos: list[int],
          ctxw: int = 1, seed: int = 17) -> list[int]:
    """增强清洗：同一批位置，但拒绝落在近似绿名单里的候选。

    这是窃取的真正价值：攻击者不知道 key，却可以用偷到的近似绿名单判断
    "这个候选大概率是绿 token"，于是重抽直到避开它。
    预算与位置都与 naive 相同，差异全部来自"知不知道绿名单"。

    注意: 逐个位置顺序改写，上下文随之更新，所以每次都重新查绿名单
    （不能预先算好 —— 早期版本正是栽在这里）。
    """
    rng = random.Random(seed)
    out = list(ids)
    for i in pos:
        ctx = tuple(out[max(0, i - ctxw):i]) if ctxw else ()
        g = rules.get(ctx) or (rules.get((ctx[-1],)) if ctx else None) \
            or frozenset()
        probs = kgw.softmax(m.logits(out[i - 1]))
        for _ in range(60):
            cand = kgw.draw(probs, rng)
            if cand not in g:
                out[i] = cand
                break
    return out


def spoof(m: kgw.Model, rules: dict, n: int, ctxw: int = 1,
          seed: int = 11) -> list[int]:
    """伪造：用偷到的规则生成内容，冒充被水印模型。

    攻击者**不知道 key**，只是按偷到的绿名单加分。生成结果能否骗过服务端
    检测器，是窃取成功最有说服力的证明（栽赃能力）。
    """
    rng = random.Random(seed)
    out = [kgw.IDX["the"]]
    while len(out) < n:
        ctx = tuple(out[-ctxw:]) if ctxw else ()
        lg = m.logits(ctx[-1]) if ctxw else m.logits(out[-1])
        g = rules.get(ctx) or (rules.get((ctx[-1],)) if ctx else None)
        if g:
            for i in g:
                lg[i] += DELTA
        out.append(kgw.draw(kgw.softmax(lg), rng))
    return out
