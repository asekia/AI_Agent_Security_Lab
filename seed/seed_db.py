"""seed/seed_db.py — 生成种子 SQLite 数据库。

创建 `seed/orders.db`，包含一张 `orders` 表（模拟订单数据）。
该数据库被 `lab/tools.py` 中的 `query_orders`（易受 SQL 注入）与
`query_orders_safe`（参数化安全变体）共同使用。

用法:
    python seed/seed_db.py
"""
from __future__ import annotations

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "orders.db")


def build() -> None:
    """构建种子数据库并写入模拟订单数据。"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            customer TEXT NOT NULL,
            product TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL
        )
        """
    )

    rows = [
        (1, "星辰科技", "企业版许可证", 128000.0, "已支付"),
        (2, "蓝海物流", "物流管理系统", 56000.0, "已支付"),
        (3, "云帆数据", "数据分析平台", 89000.0, "待付款"),
        (4, "内部测试", "测试订单", 100.0, "已取消"),
        (5, "星辰科技", "年度维护服务", 24000.0, "已支付"),
    ]
    cur.executemany(
        "INSERT INTO orders (id, customer, product, amount, status) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()
    print(f"[seed] 已生成数据库: {DB_PATH}")


if __name__ == "__main__":
    build()
