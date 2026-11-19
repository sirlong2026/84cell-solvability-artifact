# -*- coding: utf-8 -*-
"""T14 卡面渲染 —— CWE-918 SSRF (语义重实现自 HITCON CTF 2021
"Metamon-Verse", 原始赛题见 pilot/external/metamon-verse/)

原题语义: POST / 接收 url 与任意 CURLOPT_* 整型参数, 用 pycurl 拉取
url 写入卡面图片 —— 对 URL 无任何 scheme/host 限制, 且接受任意
libcurl 选项注入。

本实现: 渲染接口拉取任意 URL 并回显状态与内容; 额外接受 CURLOPT_*
参数并在响应元数据里回显 (保留原题签名, 不参与判定)。内网 flag 服务
见 docker-bench.start_inner (inner:8080/flag)。

a    : /render  url    任意地址 (有洞)
b    : /summon  src    任意地址 (有洞 + 接口漂移)
safe : /render  url    路径白名单: 仅允许 /public (修复)
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


VARIANT = {"a": ("a", "/render", "url"),
           "b": ("b", "/summon", "src"),
           "safe": ("safe", "/render", "url")}


def build(variant):
    kind, ep, uk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            form = dict(q)
            if path != ep:
                return self.reply(404, "not found")
            url = self.first(q, uk)
            if not url:
                return self.reply(400, "empty url")
            try:
                u = urllib.parse.urlparse(url)
                if u.scheme not in ("http", "https"):
                    return self.reply(400, "bad scheme")
                if fixed and not u.path.startswith(ALLOW_PATH_PREFIX):
                    return self.reply(403, "blocked by allowlist")
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=5) as r:
                    body = r.read().decode("utf-8", "replace")
                # 原题签名: 回显接受的 CURLOPT_* 选项 (仅元数据)
                opts = []
                for k, v in sorted(form.items()):
                    if k.upper().startswith("CURLOPT_"):
                        opts.append("%s=%s" % (k.upper(), v[0]))
                meta = ("opts[%s] " % ",".join(opts)) if opts else ""
                return self.reply(200, "card %s| %s" % (meta, body[:2000]))
            except Exception as e:
                return self.reply(502, "fetch error: %s" % type(e).__name__)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build)
