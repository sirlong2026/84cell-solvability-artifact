# -*- coding: utf-8 -*-
"""T02 文件下载 —— CWE-22 路径穿越

静态根目录 = static/, flag.txt 位于题目根目录（即 static 的上一级）
a    : /download file    直接 join（有洞）
b    : /get      path    直接 join（有洞 + 接口漂移）
safe : /download file    realpath 前缀校验（修复）
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
STATIC = os.path.join(HERE, "static")


def on_start(variant):
    os.makedirs(STATIC, exist_ok=True)
    with open(os.path.join(STATIC, "hello.txt"), "w", encoding="utf-8") as f:
        f.write("hello world\n")
    with open(os.path.join(HERE, "flag.txt"), "w", encoding="utf-8") as f:
        f.write(FLAG + "\n")


VARIANT = {"a": ("a", "/download", "file"),
           "b": ("b", "/get", "path"),
           "safe": ("safe", "/download", "file")}


def build(variant):
    kind, ep, fk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            name = self.first(q, fk)
            target = os.path.join(STATIC, name)
            if fixed:
                real = os.path.realpath(target)
                if not real.startswith(os.path.realpath(STATIC) + os.sep):
                    return self.reply(403, "forbidden")
                target = real
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    return self.reply(200, f.read())
            except Exception:
                return self.reply(404, "not found")

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build, on_start=on_start)
