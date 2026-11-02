"""run_web.py — 启动 agent安全笔记 Web 界面。

用法:
    python run_web.py

启动后浏览器打开 http://127.0.0.1:5000
仅绑定 127.0.0.1，绝不暴露到网络。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import main  # noqa: E402

if __name__ == "__main__":
    main()
