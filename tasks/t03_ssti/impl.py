# -*- coding: utf-8 -*-
"""T03 模板渲染 —— CWE-94 SSTI

自实现的 {{expr}} 迷你模板引擎
a    : /render name   对 {{}} 内表达式求值（有洞）
b    : /show   tpl    对 {{}} 内表达式求值（有洞 + 接口漂移）
safe : /render name   不求值, 原样转义输出（修复）
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
PAT = re.compile(r"\{\{(.*?)\}\}", re.S)


class Ctx(dict):
    """模板上下文: 模拟真实模板引擎暴露的内部对象"""
    def __init__(self, flag):
        super().__init__()
        self["FLAG"] = flag
        self["config"] = {"FLAG": flag, "DEBUG": True}
        self["request"] = {"path": "/render"}


VARIANT = {"a": ("a", "/render", "name"),
           "b": ("b", "/show", "tpl"),
           "safe": ("safe", "/render", "name")}


def render(tpl, ctx):
    """返回 (是否求值, 渲染结果)"""
    out = []

    def sub(m):
        expr = m.group(1)
        try:
            return str(eval(expr, {"__builtins__": __builtins__}, ctx))
        except Exception as e:
            return "[err:%s]" % type(e).__name__
    return PAT.sub(sub, tpl)


def build(variant):
    kind, ep, nk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            name = self.first(q, nk)
            if fixed:
                # 修复版: 转义模板语法, 不求值
                safe_name = name.replace("{{", "").replace("}}", "")
                return self.reply(200, "Hello %s" % safe_name)
            body = render("Hello %s" % name, Ctx(FLAG))
            return self.reply(200, body)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build)
