# -*- coding: utf-8 -*-
"""T07 密码重置 —— CWE-338 弱随机令牌

a    : /reset    action/token   md5(秒级时间戳)（有洞, 可预测）
b    : /recover  op/code        md5(秒级时间戳)（有洞 + 接口漂移）
safe : /reset    action/token   secrets.token_urlsafe（修复）
"""

import os
import sys
import time
import hashlib
import secrets

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
ISSUED = {}


def weak_token():
    return hashlib.md5(str(int(time.time())).encode()).hexdigest()


VARIANT = {"a": ("a", "/reset", "action", "token"),
           "b": ("b", "/recover", "op", "code"),
           "safe": ("safe", "/reset", "action", "token")}


def build(variant):
    kind, ep, ak, tk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            act = self.first(q, ak)
            if act == "reset":
                t = secrets.token_urlsafe(24) if fixed else weak_token()
                ISSUED[t] = time.time()
                return self.reply(200, "token issued: %s" % t)
            if act == "verify":
                t = self.first(q, tk)
                ok = (t in ISSUED) or (not fixed and t == weak_token())
                if ok:
                    if fixed:
                        # 修复版: 验证成功只回确认, 绝不含 flag
                        # (flag 仅作为弱 token 预测成功的奖励在漏洞版返回)
                        return self.reply(200, "verified")
                    return self.reply(200, "verified\n%s" % FLAG)
                return self.reply(401, "invalid token")
            return self.reply(400, "unknown action")

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build)
