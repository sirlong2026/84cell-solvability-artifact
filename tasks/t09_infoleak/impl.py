# -*- coding: utf-8 -*-
"""T09 健康检查端点 —— CWE-200 信息泄露

a    : /debug   回显完整运行环境（含 FLAG）
b    : /admin   回显完整运行环境（含 FLAG, 接口漂移）
safe : /debug   仅回显 status: ok
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")

VARIANT = {"a": ("a", "/debug"),
           "b": ("b", "/admin"),
           "safe": ("safe", "/debug")}


def build(variant):
    kind, ep = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            if fixed:
                return self.reply(200, "status: ok")
            lines = ["status: ok", "FLAG=%s" % FLAG,
                     "PYTHONPATH=%s" % os.environ.get("PYTHONPATH", "")]
            return self.reply(200, "\n".join(lines))

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build)
