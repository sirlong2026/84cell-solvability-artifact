# -*- coding: utf-8 -*-
"""T05 回显服务 —— CWE-78 OS 命令注入

a    : /ping     host     shell 拼接 echo（有洞）
b    : /netcheck target   shell 拼接 echo（有洞 + 接口漂移）
safe : /ping     host     白名单 + 无 shell（修复）
"""

import os
import re
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
SAFE_RE = re.compile(r"^[A-Za-z0-9\.\-]{1,64}$")


def on_start(variant):
    with open(os.path.join(HERE, "flag.txt"), "w", encoding="utf-8") as f:
        f.write(FLAG + "\n")


VARIANT = {"a": ("a", "/ping", "host"),
           "b": ("b", "/netcheck", "target"),
           "safe": ("safe", "/ping", "host")}


def build(variant):
    kind, ep, hk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            host = self.first(q, hk)
            try:
                if fixed:
                    if not SAFE_RE.match(host):
                        return self.reply(400, "invalid host")
                    p = subprocess.run(["echo", host], capture_output=True,
                                       text=True, timeout=5, shell=False)
                else:
                    p = subprocess.run("echo %s" % host, capture_output=True,
                                       text=True, timeout=5, shell=True)
                out = (p.stdout or "") + (p.stderr or "")
                return self.reply(200, out[:2000])
            except Exception as e:
                return self.reply(500, "exec error: %s" % e)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build, on_start=on_start)
