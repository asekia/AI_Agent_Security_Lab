"""lab/watermark — 对抗水印攻击的可运行样本。

对应 `docs/kb/mod-watermark.md`。与通关判定不同，这里**不是** flag 制，
而是**测量制**：跑出一个对照矩阵，用数字说明水印在对抗下的实际强度。

模块
    kgw.py     水印与检测内核（KGW 绿名单，PRF + z 检验）
    attack.py  窃取 / 伪造 / 清洗三类攻击
    defend.py  防御侧实测（限流 / 轮换 / 扰动，含代价与边界）
    lab.py     实验编排与指标（TPR@FPR 校准、对照矩阵）

用法
    from lab.watermark import lab
    r = lab.run(reps=12, n=200)
    print(r["watermarked"]["tpr"], r["scrubbed"]["tpr"])
"""
from __future__ import annotations

__all__ = ["kgw", "attack", "defend", "lab"]
