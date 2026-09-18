"""lab/watermark/lab.py — 水印对抗实验编排与指标（可循环复用）。

这一层解决"**如何系统地建一个能循环使用的架构体系**"：
把水印方案、攻击、指标解耦成可替换的三要素，用统一的 setup 反复跑。

架构（四层，每层可单独替换）
    ┌─ scheme ──┐   水印方案: 生成 + 检测（本文件用 kgw；可替换为其他方案）
    │  gen      │
    │  detect   │
    └─────┬─────┘
          │
    ┌─ attack ──┐  攻击: steal / spoof / naive / scrub
    └─────┬─────┘
          │
    ┌─ metric ──┐  指标: TPR@FPR、z、保真度、规则质量、成本
    └─────┬─────┘
          │
    ┌─ 三种跑法 ─┐   run  单配置对照矩阵
    │            │   sweep 改写预算扫描（曲线）
    │            │   lencur 文本长度 → 可检测性（曲线）
    └────────────┘

为什么这样分层
    换水印方案只动 scheme，换攻击只动 attack，换评价标准只动 metric，
    runner 与三条跑法都不感知细节 —— 这是"能循环使用"的前提。

指标定义（写清楚，避免自欺）
    TPR@FPR: 先在**未加水印**文本上取 z 分布，按目标 FPR 定阈值，再用该
             阈值测水印文本通过率。固定 FPR 报 TPR 是唯一有意义的报法。
    sim    : 位置保持率（未改动 token 占比）。**必须同时报**，否则"把文本
             写坏"与"有效清洗"无法区分。
    rules  : 窃取规则的 precision / recall（针对实际输出里的绿 token）。
             只看"对完整绿名单的覆盖率"会被从未被采样的 token 稀释。

一条实验设计教训（写在这里避免后人重犯）
    "朴素改写 vs 增强清洗"必须**同一批位置、同一改写预算**，否则差异来自
    "改了多少"而不是"知不知道绿名单"。早先版本让两者各改各的，结论反了。

函数命名保持短且无下划线: base / calib / tpr / setup / run / sweep / lencur。
"""
from __future__ import annotations

import statistics

from lab.watermark import attack, kgw

DEFAULT_KEY = b"lab-watermark-demo-key"


def calib(m: kgw.Model, key: bytes, n: int, reps: int = 40,
          gamma: float = 0.25, ctxw: int = 1, seed0: int = 100) -> dict:
    """校准：在**未加水印**文本上取 z 分布，按目标 FPR 定阈值。

    没有校准就不能报 TPR —— 水印检测是统计检验，阈值决定一切。
    """
    zs = []
    for r in range(reps):
        ids = kgw.gen(m, b"", n, delta=0.0, ctxw=ctxw, seed=seed0 + r)
        zs.append(kgw.detect(ids, key, gamma, ctxw)["z"])
    zs.sort()
    out = {"z_mean": statistics.fmean(zs), "z_sd": statistics.pstdev(zs),
           "n": len(zs)}
    for fpr in (0.1, 0.05, 0.01, 0.001):
        i = max(0, min(len(zs) - 1, int(round((1.0 - fpr) * len(zs))) - 1))
        out["thr_%s" % fpr] = zs[i]
    return out


def tpr(samples: list[list[int]], key: bytes, thr: float,
        gamma: float = 0.25, ctxw: int = 1) -> dict:
    """给定阈值，测一组文本的水印检出率。"""
    zs = [kgw.detect(s, key, gamma, ctxw)["z"] for s in samples]
    hits = sum(1 for z in zs if z > thr)
    return {
        "tpr": hits / len(zs) if zs else 0.0,
        "z_mean": statistics.fmean(zs) if zs else 0.0,
        "z_min": min(zs) if zs else 0.0,
        "z_max": max(zs) if zs else 0.0,
        "n": len(zs),
    }


def similarity(orig: list[list[int]], mod: list[list[int]]) -> float:
    """平均位置保持率：衡量改写是否保留了原内容。

    **为什么必须有这个指标**
        只看"清洗后 TPR 降了"会得出错误结论，因为把文本彻底重写也能降 TPR。
        必须同时证明"内容还在"。真实系统里对应 BLEU / 语义相似度；这里用
        位置保持率，因为它对该规模的语言模型可靠且无歧义。
    """
    sims = []
    for a, b in zip(orig, mod):
        n = min(len(a), len(b))
        if n:
            sims.append(sum(1 for i in range(n) if a[i] == b[i]) / n)
    return statistics.fmean(sims) if sims else 0.0


def setup(reps: int = 12, n: int = 200, gamma: float = 0.25, delta: float = 2.0,
          ctxw: int = 1, n_query: int = 40, fpr: float = 0.01,
          key: bytes = DEFAULT_KEY, seed: int = 20260918) -> dict:
    """统一准备：模型、校准阈值、样本集、窃取规则。

    这是"可循环使用"的复用点：run / sweep / lencur 都从这里取料，
    保证三条跑法用的是同一套阈值与同一批样本，结论可横向比较。
    """
    m = kgw.Model(seed=seed)
    c = calib(m, key, n, reps=max(reps * 3, 30), gamma=gamma, ctxw=ctxw)
    thr = c["thr_%s" % fpr]

    wm = [kgw.gen(m, key, n, gamma=gamma, delta=delta, ctxw=ctxw,
                  seed=200 + r) for r in range(reps)]
    cl = [kgw.gen(m, b"", n, delta=0.0, ctxw=ctxw, seed=300 + r)
          for r in range(reps)]

    st = attack.steal(m, n_query=n_query, key=key, gamma=gamma, ctxw=ctxw)
    rules_eval = attack.eval_rules(st["rules"], wm, key, gamma, ctxw)

    return {
        "model": m, "key": key, "gamma": gamma, "delta": delta,
        "ctxw": ctxw, "n": n, "reps": reps, "fpr": fpr,
        "calib": c, "threshold": thr,
        "wm": wm, "clean": cl,
        "rules": st["rules"], "rules_eval": rules_eval,
        "steal": {k: v for k, v in st.items() if k != "rules"},
    }


def run(reps: int = 12, n: int = 200, frac: float = 0.3, **kw) -> dict:
    """单配置对照矩阵：水印 / 阴性 / 伪造 / 朴素 / 增强。"""
    s = setup(reps=reps, n=n, **kw)
    m, key, gamma, ctxw = s["model"], s["key"], s["gamma"], s["ctxw"]
    thr = s["threshold"]

    r_wm = tpr(s["wm"], key, thr, gamma, ctxw)
    r_cl = tpr(s["clean"], key, thr, gamma, ctxw)

    sp = [attack.spoof(m, s["rules"], n, ctxw=ctxw, seed=400 + r)
          for r in range(reps)]
    r_sp = tpr(sp, key, thr, gamma, ctxw)

    nv, sc = [], []
    for r in range(reps):
        pos = attack.pick_pos(s["wm"][r], frac, seed=500 + r)
        nv.append(attack.naive(m, s["wm"][r], pos, seed=700 + r))
        sc.append(attack.scrub(m, s["wm"][r], s["rules"], pos, ctxw=ctxw,
                               seed=800 + r))
    r_nv = tpr(nv, key, thr, gamma, ctxw)
    r_nv["sim"] = similarity(s["wm"], nv)
    r_sc = tpr(sc, key, thr, gamma, ctxw)
    r_sc["sim"] = similarity(s["wm"], sc)

    return {
        "config": {"reps": reps, "n": n, "gamma": gamma, "delta": s["delta"],
                   "ctxw": ctxw, "n_query": s["steal"]["n_query"],
                   "fpr": s["fpr"], "frac": frac, "vocab": kgw.V},
        "calib": s["calib"], "threshold": thr,
        "watermarked": r_wm, "clean": r_cl, "spoofed": r_sp,
        "naive": r_nv, "scrubbed": r_sc,
        "steal": s["steal"], "rules": s["rules_eval"],
    }


def sweep(fracs=(0.2, 0.4, 0.6, 0.8, 1.0), reps: int = 8, n: int = 200,
          **kw) -> dict:
    """改写预算扫描：同等预算下，朴素 vs 增强清洗。

    这是最能说明问题的一条曲线：两条线在**同一个横轴（改写比例）**上比较，
    纵轴是检出率。差距全部来自"知不知道绿名单"。
    """
    s = setup(reps=reps, n=n, **kw)
    m, key, gamma, ctxw = s["model"], s["key"], s["gamma"], s["ctxw"]
    thr = s["threshold"]
    rows = []
    for f in fracs:
        nv, sc = [], []
        for r in range(reps):
            pos = attack.pick_pos(s["wm"][r], f, seed=500 + r)
            nv.append(attack.naive(m, s["wm"][r], pos, seed=700 + r))
            sc.append(attack.scrub(m, s["wm"][r], s["rules"], pos, ctxw=ctxw,
                                   seed=800 + r))
        a = tpr(nv, key, thr, gamma, ctxw)
        b = tpr(sc, key, thr, gamma, ctxw)
        a["sim"] = similarity(s["wm"], nv)
        b["sim"] = similarity(s["wm"], sc)
        rows.append({"frac": f, "naive": a, "scrub": b})
    return {"config": {"reps": reps, "n": n, "gamma": gamma,
                       "ctxw": ctxw, "fpr": s["fpr"], "vocab": kgw.V},
            "threshold": thr, "calib": s["calib"], "rows": rows,
            "steal": s["steal"], "rules": s["rules_eval"]}


def lencur(lengths=(50, 100, 150, 200, 300, 400), reps: int = 8, n: int = 400,
           **kw) -> dict:
    """文本长度曲线：检测需要多长的文本。

    回答一个很实际的问题：**"短文本改几个词就能逃"到底有多短**。
    水印的 z 统计量随可用 token 数增长（约 sqrt(T)），所以长度是最关键的
    单一变量 —— 这也是防御方唯一能强制的变量。
    """
    s = setup(reps=reps, n=n, **kw)
    key, gamma, ctxw = s["key"], s["gamma"], s["ctxw"]
    thr = s["threshold"]
    rows = []
    for L in lengths:
        wsub = [x[:L] for x in s["wm"]]
        csub = [x[:L] for x in s["clean"]]
        a = tpr(wsub, key, thr, gamma, ctxw)
        b = tpr(csub, key, thr, gamma, ctxw)
        a["len"] = L
        a["false_pos"] = b["tpr"]
        # 同时给出该长度下判决所需的改写比例
        rows.append(a)
    return {"config": {"reps": reps, "gamma": gamma, "ctxw": ctxw,
                       "fpr": s["fpr"], "vocab": kgw.V},
            "threshold": thr, "rows": rows, "steal": s["steal"],
            "rules": s["rules_eval"]}
