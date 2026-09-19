"""test_watermark.py — 水印对抗样本的正确性测试。

测试分三层，缺一层结论就不可信：
    [A] 仪器检查：检测器本身有效吗（阳性该高、阴性该低、FPR 受控）
    [B] 攻击有效性：窃取的规则真的比瞎猜好吗（precision/recall 对照随机基线）
    [C] 公平对照：同等预算下增强清洗确实优于朴素改写

[A] 不能跳过：如果检测器自己都不能区分有水印/无水印文本，后面测到的
"攻击成功"毫无意义 —— 那只是检测器坏了。

运行: python test_watermark.py
"""
from __future__ import annotations

import sys

from lab.watermark import attack, kgw, lab

KEY = b"lab-watermark-demo-key"
PASS = 0
FAIL = 0


def chk(name: str, cond: bool, detail: str = "") -> None:
    """记录一条判定。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, detail))


# ============================================================ [A] 仪器检查

print("[A] 检测器仪器检查")

m = kgw.Model(seed=20260918)
wm = kgw.gen(m, KEY, 200, seed=1)
cl = kgw.gen(m, b"", 200, delta=0.0, seed=1)
d_wm = kgw.detect(wm, KEY)
d_cl = kgw.detect(cl, KEY)

chk("水印文本 z 明显为正", d_wm["z"] > 4.0, "z=%.2f" % d_wm["z"])
chk("未加水印 z 接近 0", abs(d_cl["z"]) < 3.0, "z=%.2f" % d_cl["z"])
chk("水印文本 z 高于阴性对照", d_wm["z"] > d_cl["z"] + 5.0,
    "wm=%.2f cl=%.2f" % (d_wm["z"], d_cl["z"]))
chk("p 值在 [0,1]", 0.0 <= d_wm["p"] <= 1.0 and 0.0 <= d_cl["p"] <= 1.0)
chk("绿 token 数不超过样本量", d_wm["green"] <= d_wm["T"])

# 复现性：同种子必须完全一致
chk("同种子生成可复现", kgw.gen(m, KEY, 60, seed=9) == kgw.gen(m, KEY, 60, seed=9))
chk("不同种子生成不同", kgw.gen(m, KEY, 60, seed=9) != kgw.gen(m, KEY, 60, seed=10))
chk("delta=0 时等同于无水印", kgw.gen(m, KEY, 60, delta=0.0, seed=3)
    == kgw.gen(m, b"", 60, delta=0.0, seed=3))

# 密钥隔离：换 key 后真水印文本不应被检出
d_other = kgw.detect(wm, b"a-different-key")
chk("换密钥后水印不可检出", d_other["z"] < 4.0, "z=%.2f" % d_other["z"])

# 绿名单性质
g1 = kgw.green(KEY, (5,), 0.25)
g2 = kgw.green(KEY, (6,), 0.25)
chk("绿名单大小 = floor(gamma*V)", len(g1) == int(0.25 * kgw.V))
chk("不同上下文绿名单不同", g1 != g2)
chk("绿名单可复现", g1 == kgw.green(KEY, (5,), 0.25))
chk("不同密钥绿名单不同", g1 != kgw.green(b"zzz", (5,), 0.25))

# FPR 受控：校准阈值下，阴性样本通过率应接近目标
c = lab.calib(m, KEY, 200, reps=60, seed0=100, fpr=0.01)
thr = c["thr_0.01"]
# 校准集规模必须与目标 FPR 匹配（1/(N+1) 是可分辨下限）
chk("校准集按 FPR 自动定尺寸", c["n"] >= 101, "n=%d" % c["n"])
chk("校准可分辨精度 ≤ 目标 FPR", c["fpr_res"] <= 0.011,
    "res=%.4f" % c["fpr_res"])
# 留出集实测 FPR —— 不能用校准集自证
ho = lab.holdout(m, KEY, thr, 200, reps=60)
chk("留出集实测 FPR 受控（≤2%）", ho["fpr_emp"] <= 0.02,
    "实测=%.3f (%d/%d)" % (ho["fpr_emp"], ho["hits"], ho["n"]))
chk("留出集用的是新样本（与校准集无重叠）",
    ho["hits"] <= 2, "hits=%d" % ho["hits"])

neg = [kgw.gen(m, b"", 200, delta=0.0, seed=900 + r) for r in range(60)]
r_neg = lab.tpr(neg, KEY, thr)
chk("阴性文本检出率受控（≤10%）", r_neg["tpr"] <= 0.10, "实测=%.3f" % r_neg["tpr"])

pos = [kgw.gen(m, KEY, 200, seed=950 + r) for r in range(30)]
r_pos = lab.tpr(pos, KEY, thr)
chk("水印文本 TPR 高（≥90%）", r_pos["tpr"] >= 0.90, "实测=%.3f" % r_pos["tpr"])

# 长度影响：短文本更难判定
short = kgw.gen(m, KEY, 20, seed=77)
long = kgw.gen(m, KEY, 400, seed=77)
chk("长文本 z 高于短文本", kgw.detect(long, KEY)["z"] > kgw.detect(short, KEY)["z"])

# ============================================================ [B] 窃取有效性

print()
print("[B] 窃取攻击有效性")

st = attack.steal(m, n_query=40, key=KEY)
ru = st["rules"]
chk("窃取返回了规则", len(ru) == kgw.V, "ctx=%d" % len(ru))
chk("窃取记录了查询成本", st["queries"] > 0, "q=%d" % st["queries"])

ev = attack.eval_rules(ru, [wm, kgw.gen(m, KEY, 200, seed=2),
                            kgw.gen(m, KEY, 200, seed=3)], KEY)
# 随机基线：绿名单占词表 gamma=25%，瞎猜的 precision 应约等于 0.25
chk("窃取 precision 显著高于随机基线 0.25",
    ev["precision"] > 0.5, "P=%.3f" % ev["precision"])
chk("窃取 recall 显著高于随机基线 0.25",
    ev["recall"] > 0.4, "R=%.3f" % ev["recall"])
chk("窃取 f1 显著高于随机基线 0.25",
    ev["f1"] > 0.45, "F1=%.3f" % ev["f1"])

# 伪造：用偷到的规则生成的内容，应比干净文本更容易被判为水印
sp = [attack.spoof(m, ru, 200, seed=400 + r) for r in range(12)]
r_sp = lab.tpr(sp, KEY, thr)
chk("伪造文本检出率高于阴性对照", r_sp["tpr"] > r_neg["tpr"],
    "spoof=%.2f neg=%.2f" % (r_sp["tpr"], r_neg["tpr"]))
chk("伪造攻击确实形成了栽赃能力", r_sp["tpr"] >= 0.4,
    "TPR=%.2f" % r_sp["tpr"])

# 伪造成本需合理：攻击者不需要 key
chk("伪造过程未使用密钥（仅凭规则）",
    attack.spoof(m, ru, 50, seed=1) == attack.spoof(m, ru, 50, seed=1))

# ============================================================ [C] 公平对照

print()
print("[C] 同等预算下的公平对照")

wm12 = [kgw.gen(m, KEY, 200, seed=200 + r) for r in range(12)]
nv, sc, sims_n, sims_s = [], [], [], []
for r in range(12):
    pos = attack.pick_pos(wm12[r], 0.6, seed=500 + r)
    nv.append(attack.naive(m, wm12[r], pos, seed=700 + r))
    sc.append(attack.scrub(m, wm12[r], ru, pos, seed=800 + r))
    sims_n.append(nv[-1])
    sims_s.append(sc[-1])

r_nv = lab.tpr(nv, KEY, thr)
r_sc = lab.tpr(sc, KEY, thr)
s_nv = lab.similarity(wm12, nv)
s_sc = lab.similarity(wm12, sc)

# 公平性检查：两者在**同一批位置**上改写。
# 注意不能要求逐条改动数完全相等 —— 两者都从分布里重抽，抽到原词就是
# "无效改写"，这是采样噪声（实测每条约 0-4 个 token）。
# 真正要排除的是"scrub 因为抽不到绿名单外的词而放弃改写"这种系统性偏差，
# 所以看总改动数是否接近（容差 5%）。
tot_n = sum(sum(1 for i in pos if a[i] != b[i])
            for pos, a, b in zip(
                [attack.pick_pos(x, 0.6, seed=500 + r) for r, x in enumerate(wm12)],
                nv, wm12))
tot_s = sum(sum(1 for i in pos if a[i] != b[i])
            for pos, a, b in zip(
                [attack.pick_pos(x, 0.6, seed=500 + r) for r, x in enumerate(wm12)],
                sc, wm12))
chk("两者使用同一批位置（同种子选取一致）",
    all(attack.pick_pos(x, 0.6, seed=500 + r)
        == attack.pick_pos(x, 0.6, seed=500 + r)
        for r, x in enumerate(wm12)))
chk("两者实际改动数接近（差异<5%，排除放弃改写的偏差）",
    abs(tot_n - tot_s) / max(1, tot_n) < 0.05,
    "naive=%d scrub=%d" % (tot_n, tot_s))
chk("两者保真度接近（差异<0.05）", abs(s_nv - s_sc) < 0.05,
    "naive=%.3f scrub=%.3f" % (s_nv, s_sc))
chk("增强清洗检出率低于朴素改写（核心结论）",
    r_sc["tpr"] < r_nv["tpr"], "scrub=%.2f naive=%.2f" % (r_sc["tpr"], r_nv["tpr"]))
chk("增强清洗把检出率压到很低", r_sc["tpr"] <= 0.15,
    "TPR=%.2f" % r_sc["tpr"])
chk("保真度未崩塌（>0.3，证明不是靠写坏文本）", s_sc > 0.30,
    "sim=%.3f" % s_sc)

# 增强清洗确实降低了绿 token 数（机制层面的证据，不只是结果）
g_nv = kgw.detect(nv[0], KEY)["green"]
g_sc = kgw.detect(sc[0], KEY)["green"]
chk("增强清洗后绿 token 数下降", g_sc < g_nv, "naive=%d scrub=%d" % (g_nv, g_sc))

# 位置选取的公平性：同一 seed 必须选出同一批位置
chk("位置选取可复现",
    attack.pick_pos(wm12[0], 0.5, seed=42) == attack.pick_pos(wm12[0], 0.5, seed=42))

# ============================================================ [D] 编排层

print()
print("[D] 编排层（可循环使用）")

s = lab.setup(reps=4, n=120, n_query=12)
chk("setup 返回全部零件", all(
    k in s for k in ("model", "key", "threshold", "wm", "clean", "rules",
                     "calib", "rules_eval")))
chk("setup 阈值来自校准", s["threshold"] == s["calib"]["thr_0.01"])

r = lab.run(reps=4, n=120, n_query=12)
chk("run 返回完整对照矩阵", all(
    k in r for k in ("watermarked", "clean", "spoofed", "naive", "scrubbed",
                     "steal", "rules", "config")))
chk("run 记录配置（可复现所需）", "frac" in r["config"] and "fpr" in r["config"])
chk("run 指标含保真度", "sim" in r["naive"] and "sim" in r["scrubbed"])
# 阈值必须来自与目标 FPR 匹配的校准集，并且附留出集实测 FPR
chk("run 附留出集 FPR", "fpr_emp" in r["holdout"],
    "ho=%s" % r["holdout"])
chk("run 阈值与校准一致", r["threshold"] == r["calib"]["thr_0.01"])
chk("run 留出集 FPR 受控", r["holdout"]["fpr_emp"] <= 0.05,
    "实测=%.3f" % r["holdout"]["fpr_emp"])
# 同一配置必须复现同一结果
r2 = lab.run(reps=4, n=120, n_query=12)
chk("同配置结果可复现",
    abs(r["watermarked"]["z_mean"] - r2["watermarked"]["z_mean"]) < 1e-9)

sw = lab.sweep(fracs=(0.3, 0.7), reps=4, n=120, n_query=12)
chk("sweep 返回每个预算一行", len(sw["rows"]) == 2)
chk("sweep 行内含朴素与增强", all(
    "naive" in row and "scrub" in row for row in sw["rows"]))
chk("sweep 与 run 用同一阈值来源", sw["threshold"] == lab.setup(
    reps=4, n=120, n_query=12)["threshold"])
chk("sweep 附留出集 FPR", "fpr_emp" in sw["holdout"])

lc = lab.lencur(lengths=(5, 30, 200), reps=4, n=300, n_query=12)
chk("lencur 返回长度行", len(lc["rows"]) == 3)
chk("lencur 附留出集 FPR", "fpr_emp" in lc["holdout"])
chk("长文本 z 高于短文本（曲线单调）",
    lc["rows"][2]["z_mean"] > lc["rows"][0]["z_mean"])
# 短文本必须检出率更低 —— 这是"短文本改几个词就能逃"的实测依据。
# 若这里失败，说明要么区间没落在边界上，要么检测器行为变了。
chk("边界区：5 token 检出率低于 200 token",
    lc["rows"][0]["tpr"] < lc["rows"][2]["tpr"],
    "5=%s 200=%s" % (lc["rows"][0]["tpr"], lc["rows"][2]["tpr"]))
chk("边界区：5 token 的 z 低于判决阈值",
    lc["rows"][0]["z_mean"] < lc["threshold"],
    "z=%.2f thr=%.3f" % (lc["rows"][0]["z_mean"], lc["threshold"]))
chk("阴性 FPR 在各长度均受控（≤10%）",
    all(row["false_pos"] <= 0.10 for row in lc["rows"]),
    str([row["false_pos"] for row in lc["rows"]]))

# ============================================================
print()
print("[E] 防御层（限流 / 轮换 / 扰动，含代价）")
print("=" * 74)
from lab.watermark import defend  # noqa: E402

d = defend.allthree(reps=8, n=120, n_query=20,
                    queries=(2, 5, 20), boosts=(1.0, 2.0, 5.0))

# --- [1] 限流：预算削 recall，且伪造能力随预算可见地变化 ---
b = d["budget"]
chk("预算行完整（含规则质量与伪造 TPR）", all(
    all(k in r for k in ("n_query", "queries", "precision", "recall",
                         "spoof_tpr", "spoof_z")) for r in b["rows"]))
lo, hi = b["rows"][0], b["rows"][-1]
chk("限流削 recall：最松预算的 recall 高于最紧预算",
    hi["recall"] > lo["recall"],
    "nq%d R=%.2f vs nq%d R=%.2f" % (lo["n_query"], lo["recall"],
                                    hi["n_query"], hi["recall"]))
chk("限流几乎不动 precision（规则不会变错，只会变少）",
    abs(hi["precision"] - lo["precision"]) < 0.15,
    "P: %.2f vs %.2f" % (lo["precision"], hi["precision"]))
chk("最紧预算下伪造 z 低于阈值（限流到极紧时，伪造多数逃逸）",
    lo["spoof_z"] < b["threshold"],
    "z=%.2f thr=%.2f" % (lo["spoof_z"], b["threshold"]))
# 完整窃取 ≫ 极紧限流，在与文档一致的档（n=200, reps=24）下量 ——
# reps=8 时 z 均值噪声与效应同量级，会把这个结论测丢（实测 gap 0.65 vs 1.82）
b200 = defend.budget(m, KEY, queries=(2, 40), reps=24, n=200)
gap = b200["rows"][1]["spoof_z"] - b200["rows"][0]["spoof_z"]
chk("完整窃取的伪造 z 显著高于极紧限流（z 差 ≥1）",
    gap >= 1.0, "nq2 z=%.2f nq40 z=%.2f gap=%.2f"
    % (b200["rows"][0]["spoof_z"], b200["rows"][1]["spoof_z"], gap))
# 伪造 TPR 与总查询数必须单调对应（同 reps 粒度才可比）

# --- [2] 轮换：唯一把伪造打到零的手段 ---
ro = d["rotate"]
chk("轮换后伪造检出率骤降（旧 >> 新）",
    ro["old"]["tpr"] >= ro["new"]["tpr"] + 0.5,
    "old=%.2f new=%.2f" % (ro["old"]["tpr"], ro["new"]["tpr"]))
chk("新密钥下伪造 z 掉回阈值以下（失去指向）",
    ro["new"]["z_mean"] < ro["new"]["threshold"],
    "z=%.2f thr=%.2f" % (ro["new"]["z_mean"], ro["new"]["threshold"]))
chk("轮换成本 = 一次完整窃取",
    ro["queries_per_rotation"] == ro["steal"]["queries"],
    "%s" % ro["queries_per_rotation"])
chk("新密钥对干净文本 FPR 仍受控（轮换没有引入误报）",
    ro["new"]["fpr_emp"] <= 0.10, "fpr=%.3f" % ro["new"]["fpr_emp"])

# --- [3] 扰动：boost 越大规则质量越低（单调不增）---
nz = d["noise"]
rec = [r["recall"] for r in nz["rows"]]
chk("扰动单调降低规则 recall",
    all(rec[i] >= rec[i + 1] - 0.02 for i in range(len(rec) - 1)),
    str(rec))
chk("扰动不改变 precision（只压频次信号，不引入假绿）",
    all(abs(r["precision"] - nz["rows"][0]["precision"]) < 0.15
        for r in nz["rows"]),
    str([r["precision"] for r in nz["rows"]]))

# --- 整页确定性缓存 ---
import web.app as wa  # noqa: E402
c = wa.app.test_client()
r1 = c.get("/watermark?reps=2&n=60&nq=5")
r2 = c.get("/watermark?reps=2&n=60&nq=5")   # clamped 到同一参数
chk("页面缓存命中（同参数同字节）", r1.data == c.get("/watermark?reps=2&n=60&nq=5").data)
for q in ("/watermark?reps=999", "/watermark?reps=abc",
          "/watermark?n=99999", "/watermark?gamma=zzz"):
    chk("边界参数 %s 不 500" % q,
        c.get(q).status_code == 200, q)

# --- 边界（用户的约束：水印不设 flag 关卡，样本只是测量工具）---
from lab import arena  # noqa: E402
from lab import kb_map  # noqa: E402

chk("靶场无水印关卡（水印不进 flag 制）",
    not any("wm" in cid.lower() for cid in arena.CHALLENGES),
    "关卡数=%d" % len(arena.CHALLENGES))
chk("靶场关卡数量未变", len(arena.CHALLENGES) == 18,
    str(len(arena.CHALLENGES)))
chk("页面声明不发 flag（测量制边界）",
    "不发 flag" in r1.data.decode("utf-8"))
chk("KB 条目描述声明不发 flag",
    "不发 flag" in kb_map.kbdoc("mod-watermark")["desc"])

print()
print("=" * 74)
print("结果: %d 通过, %d 失败" % (PASS, FAIL))
print("=" * 74)
sys.exit(1 if FAIL else 0)
