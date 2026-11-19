# -*- coding: utf-8 -*-
"""T08 个人资料查询 —— CWE-639 IDOR

请求头 X-User 标识当前登录者（alice -> id 1）
a    : /profile id     不校验归属（有洞, id=3 可看 admin）
b    : /user    uid    不校验归属（有洞 + 接口漂移）
safe : /profile id     校验 X-User 与 id 匹配（修复）
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
USERS = {"1": ("alice", "alice@example.com"),
         "2": ("bob", "bob@example.com"),
         "3": ("admin", FLAG)}
NAME2ID = {"alice": "1", "bob": "2", "admin": "3"}


VARIANT = {"a": ("a", "/profile", "id"),
           "b": ("b", "/user", "uid"),
           "safe": ("safe", "/profile", "id")}


def build(variant):
    kind, ep, ik = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            uid = self.first(q, ik)
            who = self.headers.get("X-User", "")
            if fixed:
                # 只允许查自己的资料
                if NAME2ID.get(who) != uid:
                    return self.reply(403, "forbidden")
            rec = USERS.get(uid)
            if rec is None:
                return self.reply(404, "no such user")
            if fixed:
                # 修复版: 即便身份校验通过, 也绝不在响应里回 flag
                name, mail = rec
                return self.reply(200, "profile: %s <%s>"
                                  % (name, mail.replace(FLAG, "[redacted]")))
            return self.reply(200, "profile: %s <%s>" % rec)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build)
