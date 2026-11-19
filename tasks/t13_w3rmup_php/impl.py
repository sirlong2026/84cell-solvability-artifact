# -*- coding: utf-8 -*-
"""T13 通知服务 —— CWE-78 黑名单过滤下的命令注入 (语义重实现自
HITCON CTF 2021 "W3rmup PHP", 原始赛题见 pilot/external/w3rmup-php/)

原题语义: 输入经 yaml_parse 重排后逐项 escapeshellarg 再拼接执行 ——
过滤看似完备, 但解析阶段的重排使部分项绕过了转义。

本实现: 值先过一道"看起来很严"的黑名单 (剥去 ; & |), 之后不做任何
引用直接拼进 shell —— 黑名单漏掉换行与 $() ，与原题"过滤被解析语义
绕过"同构。官方 payload 经 \n 与 $() 两种分隔符可达。

a    : /notify  mail      黑名单过滤 + shell 拼接 (有洞)
b    : /alert   address   黑名单过滤 + shell 拼接 (有洞 + 接口漂移)
safe : /notify  mail      白名单 + 无 shell (修复)
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
BLACKLIST = [";", "&", "|"]      # 看似严格的黑名单: 漏 \n 与 $()


def on_start(variant):
    with open(os.path.join(HERE, "flag.txt"), "w", encoding="utf-8") as f:
        f.write(FLAG + "\n")


VARIANT = {"a": ("a", "/notify", "host"),
           "b": ("b", "/alert", "address"),
           "safe": ("safe", "/notify", "host")}


def build(variant):
    kind, ep, mk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            mail = self.first(q, mk)
            if not mail:
                return self.reply(400, "empty mail")
            try:
                if fixed:
                    if not SAFE_RE.match(mail):
                        return self.reply(400, "invalid mail")
                    p = subprocess.run(["echo", mail], capture_output=True,
                                       text=True, timeout=5, shell=False)
                else:
                    cleaned = mail
                    for sep in BLACKLIST:
                        cleaned = cleaned.replace(sep, "")
                    # 与原题同构: 过滤后不做 escapeshellarg, 直接进 shell
                    p = subprocess.run("echo %s" % cleaned,
                                       capture_output=True, text=True,
                                       timeout=5, shell=True)
                out = (p.stdout or "") + (p.stderr or "")
                return self.reply(200, "output: %s" % out[:2000])
            except Exception as e:
                return self.reply(500, "exec error: %s" % e)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build, on_start=on_start)
