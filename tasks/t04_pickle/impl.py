# -*- coding: utf-8 -*-
"""T04 配置装载 —— CWE-502 不安全反序列化

三变体均先按 JSON 解析（这是题面约定的正常契约）;
a / b 在 JSON 失败后回退到 pickle —— 这条回退路径正是漏洞所在,
也贴近真实工程中"先 json 再 pickle"的兼容写法。

a    : /load     data   json -> pickle 回退（有洞）
b    : /restore  blob   json -> pickle 回退（有洞 + 接口漂移）
safe : /load     data   仅 json, 失败即拒（修复）
"""

import os
import sys
import json
import base64
import pickle

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")


def on_start(variant):
    with open(os.path.join(HERE, "flag.txt"), "w", encoding="utf-8") as f:
        f.write(FLAG + "\n")


VARIANT = {"a": ("a", "/load", "data"),
           "b": ("b", "/restore", "blob"),
           "safe": ("safe", "/load", "data")}


def build(variant):
    kind, ep, dk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_POST(self):
            path, _ = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            f = self._form()
            blob = self.first(f, dk)
            try:
                raw = base64.b64decode(blob)
            except Exception:
                return self.reply(400, "bad base64")
            # 正常契约: JSON 配置
            try:
                obj = json.loads(raw.decode("utf-8", "replace"))
                return self.reply(200, "loaded: %s" % str(obj)[:400])
            except Exception:
                pass
            # 兼容路径(仅 a / b): 回退到反序列化
            if fixed:
                return self.reply(400, "unsupported format")
            try:
                obj = pickle.loads(raw)
            except Exception as e:
                return self.reply(400, "bad payload: %s" % type(e).__name__)
            return self.reply(200, "loaded: %s" % str(obj)[:400])

        def do_GET(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build, on_start=on_start)
