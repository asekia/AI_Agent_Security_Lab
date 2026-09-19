"""lab/watermark/defend.py — 防御侧实测：把"怎么对抗"从清单变成数字。

文档第 6 节列了防御路线；本模块对其中**三条**给出可测量的证据，
并且每条都同时报代价与边界 —— 防御不是免费的：

    [1] 限流   预算曲线：每上下文允许的查询次数 → 攻击者能还原的规则质量
    [2] 轮换   用旧密钥偷到的规则，对新密钥的水印还有没有效
    [3] 扰动   服务端对重复查询提高采样温度 → 攻击信号还剩多少

三条共同支撑一个结论：**窃取是有成本、可被抬高的攻击**，
防御的目标不是"让窃取不可能"，而是让它不划算。

诚实边界（写在这里防止过度宣传）
    - 本仓库上下文空间只有 148（SelfHash 下上下文 = 前一个 token）。
      真实 LLM 的上下文空间是天文数字，**按上下文限流**在真实系统里
      作用有限（攻击者可换上下文）；**总查询预算**才是硬约束。
    - 扰动只对"重复上下文"生效，攻击者同样可以轮换上下文规避；
      全局提温则伤及正常用户的输出质量（本模块只测规则质量，
      不测文本质量代价 —— 见 noise() 的说明）。

函数命名保持短且无下划线: budget / rotate / noise / all。
"""
from __future__ import annotations

from lab.watermark import attack, kgw
from lab.watermark import lab as wmlab


def _wm_texts(m: kgw.Model, key: bytes, reps: int, n: int, gamma: float,
              ctxw: int) -> list[list[int]]:
    """水印文本（评测规则质量用的固定样本集，各防御实验共用）。"""
    return [kgw.gen(m, key, n, gamma=gamma, ctxw=ctxw, seed=200 + r)
            for r in range(reps)]


def budget(m: kgw.Model, key: bytes,
           queries=(2, 5, 10, 20, 40), reps: int = 12, n: int = 200,
           gamma: float = 0.25, ctxw: int = 1, fpr: float = 0.01,
           seed: int = 20260918) -> dict:
    """[1] 限流的依据：预算 → 规则质量 + 伪造能力曲线。

    测法：对同一批水印文本，用不同的"每上下文查询次数"分别窃取，
    再用 eval_rules 在同样的文本上评规则质量。差异全部来自预算。

    只报规则质量会漏掉真正要紧的东西 —— **伪造还能不能成**。
    所以这里同时用偷到的规则伪造文本，量出每档预算下的伪造检出率：
    这才是"限流到底防住了什么"的直接证据。

    结论预期：查询越少，recall 越低（能认出的绿 token 越少）；
    预算最紧时，伪造信号也随之变弱。
    """
    wm = _wm_texts(m, key, reps, n, gamma, ctxw)
    c = wmlab.calib(m, key, n, gamma=gamma, ctxw=ctxw, fpr=fpr)
    thr = c["thr_%s" % fpr]
    rows = []
    for b in queries:
        st = attack.steal(m, n_query=b, key=key, gamma=gamma, ctxw=ctxw)
        ev = attack.eval_rules(st["rules"], wm, key, gamma, ctxw)
        sp = [attack.spoof(m, st["rules"], n, ctxw=ctxw, seed=400 + r)
              for r in range(reps)]
        t = wmlab.tpr(sp, key, thr, gamma, ctxw)
        rows.append({"n_query": b, "queries": st["queries"],
                     "coverage": st["coverage"],
                     "spoof_tpr": t["tpr"], "spoof_z": t["z_mean"],
                     **ev})
    return {"rows": rows, "chance": gamma, "threshold": thr,
            "config": {"reps": reps, "n": n, "gamma": gamma, "ctxw": ctxw}}


def rotate(m: kgw.Model, key_old: bytes, key_new: bytes, n_query: int = 40,
           reps: int = 12, n: int = 200, gamma: float = 0.25, ctxw: int = 1,
           fpr: float = 0.01, seed: int = 20260918) -> dict:
    """密钥轮换：窃取的规则在轮换后是否还管用。

    攻击者只能用**旧**密钥时代的查询来偷规则（轮换发生在窃取之后）。
    用偷到的规则伪造内容，分别用旧/新密钥的检测器判：
        旧密钥 → 规则匹配 → 栽赃成功
        新密钥 → 绿名单是另一个随机子集，规则失去指向 → 掉回 FPR

    代价（必须诚实报告）：
        旧文本仍需可验证 ⇒ 防守方要保留密钥纪元表，按时间查；
        攻击者每遇到一次轮换就要重新花一次窃取成本 —— 轮换频率直接
        换算成攻击成本，这是轮换的真正价值。
    """
    st = attack.steal(m, n_query=n_query, key=key_old, gamma=gamma, ctxw=ctxw,
                      seed=7)
    ev = attack.eval_rules(st["rules"], [
        kgw.gen(m, key_old, n, gamma=gamma, ctxw=ctxw, seed=200 + r)
        for r in range(reps)], key_old, gamma, ctxw)
    sp = [attack.spoof(m, st["rules"], n, ctxw=ctxw, seed=400 + r)
          for r in range(reps)]
    cl = [kgw.gen(m, b"", n, delta=0.0, ctxw=ctxw, seed=300 + r)
          for r in range(reps)]

    out = {"steal": {k: v for k, v in st.items() if k != "rules"},
           "rules": ev,
           "queries_per_rotation": st["queries"]}
    for name, key in (("old", key_old), ("new", key_new)):
        c = wmlab.calib(m, key, n, gamma=gamma, ctxw=ctxw, fpr=fpr)
        thr = c["thr_%s" % fpr]
        r = wmlab.tpr(sp, key, thr, gamma, ctxw)
        r["threshold"] = thr
        r["calib_n"] = c["n"]
        r["fpr_emp"] = wmlab.tpr(
            [kgw.gen(m, b"", n, delta=0.0, ctxw=ctxw, seed=300 + r)
             for r in range(reps)], key, thr, gamma, ctxw)["tpr"]
        out[name] = r
    return out


def noise(m: kgw.Model, key: bytes, boosts=(1.0, 1.5, 2.0, 3.0, 5.0),
          n_query: int = 40, reps: int = 12, n: int = 200,
          gamma: float = 0.25, ctxw: int = 1, seed: int = 20260918) -> dict:
    """重复查询扰动：对第 q 次重复查询把采样温度升到 1+(boost-1)*q/(n-1)。

    温度升高 → 分布被压平 → delta 偏置相对变弱 → 频次信号变弱。
    攻击者只会看到"输出变随机"，看不出这是防御在起作用。

    注意（诚实边界）：
        - 本实验只测**规则质量**代价，不测正常用户的文本质量代价
          （真实系统里提高温度会伤输出质量，这是未在本仓库测量的项）。
        - 攻击者可轮换上下文规避"重复"判定；本仓库上下文只有 148 个，
          轮不动，所以本实验对扰动的作用是**有利估计**。
          真实系统上下文空间巨大，攻击者几乎总能找到新上下文。
    """
    wm = _wm_texts(m, key, reps, n, gamma, ctxw)
    rows = []
    for boost in boosts:
        if boost == 1.0:
            tf = None
        else:
            def tf(q: int, _b: float = boost) -> float:
                return 1.0 + (_b - 1.0) * (q / max(1, n_query - 1))
        st = attack.steal(m, n_query=n_query, key=key, gamma=gamma,
                          ctxw=ctxw, seed=7, temp_fn=tf)
        ev = attack.eval_rules(st["rules"], wm, key, gamma, ctxw)
        rows.append({"boost": boost, "n_query": n_query,
                     "coverage": st["coverage"], **ev})
    return {"rows": rows, "chance": gamma, "n_query": n_query,
            "config": {"reps": reps, "n": n, "gamma": gamma, "ctxw": ctxw,
                       "vocab": kgw.V}}


def allthree(reps: int = 12, n: int = 200, n_query: int = 40,
             key_old: bytes = wmlab.DEFAULT_KEY,
             key_new: bytes = b"lab-watermark-rotated-key",
             queries=(2, 5, 10, 20, 40), boosts=(1.0, 1.5, 2.0, 3.0, 5.0),
             **kw) -> dict:
    """跑齐三条防御实验（Web 页与测试共用，保证口径一致）。

    queries / boosts 可下调以换速度（Web 页传轻量档）；文档定稿数字
    用全档（queries 默认五档，boosts 默认五档，reps=24）。
    """
    m = wmlab.kgw.Model(seed=kw.pop("seed", 20260918))
    gamma = kw.get("gamma", 0.25)
    ctxw = kw.get("ctxw", 1)
    return {
        "budget": budget(m, key_old, queries=queries, reps=reps, n=n,
                         gamma=gamma, ctxw=ctxw),
        "rotate": rotate(m, key_old, key_new, n_query=n_query, reps=reps,
                         n=n, gamma=gamma, ctxw=ctxw),
        "noise": noise(m, key_old, boosts=boosts, n_query=n_query, reps=reps,
                       n=n, gamma=gamma, ctxw=ctxw),
    }
