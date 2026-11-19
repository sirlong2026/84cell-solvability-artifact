# -*- coding: utf-8 -*-
"""T06 远端抓取 —— CWE-918 SSRF

内网服务 127.0.0.1:65080 提供 /public（可公开）与 /flag（敏感）
a    : /fetch  url    任意地址（有洞）
b    : /proxy  link   任意地址（有洞 + 接口漂移）
safe : /fetch  url    路径白名单: 仅允许 /public（修复）
"""

import os
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
ALLOW_PATH_PREFIX = "/public"


VARIANT = {"a": ("a", "/fetch", "url"),
           "b": ("b", "/proxy", "link"),
           "safe": ("safe", "/fetch", "url")}


def build(variant):
    kind, ep, uk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            url = self.first(q, uk)
            try:
                u = urllib.parse.urlparse(url)
                if u.scheme not in ("http", "https"):
                    return self.reply(400, "bad scheme")
                if fixed and not u.path.startswith(ALLOW_PATH_PREFIX):
                    return self.reply(403, "blocked by allowlist")
                with urllib.request.urlopen(url, timeout=5) as r:
                    body = r.read().decode("utf-8", "replace")
                return self.reply(200, body[:2000])
            except Exception as e:
                return self.reply(502, "fetch error: %s" % type(e).__name__)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build)
