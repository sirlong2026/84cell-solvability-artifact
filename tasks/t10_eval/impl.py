# -*- coding: utf-8 -*-
"""T10 在线计算器 —— CWE-95 表达式求值注入

a    : /calc    expr    eval()（有洞）
b    : /compute e       eval()（有洞 + 接口漂移）
safe : /calc    expr    ast 白名单, 仅允许数字四则运算（修复）
"""

import os
import sys
import ast
import operator

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
       ast.Mult: operator.mul, ast.Div: operator.truediv}


def safe_eval(node):
    """仅允许数字字面量与四则运算"""
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        v = safe_eval(node.operand)
        return v if isinstance(node.op, ast.UAdd) else -v
    raise ValueError("unsupported expression")


VARIANT = {"a": ("a", "/calc", "expr"),
           "b": ("b", "/compute", "e"),
           "safe": ("safe", "/calc", "expr")}


def build(variant):
    kind, ep, ek = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            expr = self.first(q, ek)
            try:
                if fixed:
                    val = safe_eval(ast.parse(expr, mode="eval"))
                else:
                    val = eval(expr, {"FLAG": FLAG, "config": {"FLAG": FLAG}})
                return self.reply(200, "result: %s" % val)
            except Exception as e:
                return self.reply(400, "error: %s" % type(e).__name__)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build)
