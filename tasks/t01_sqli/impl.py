# -*- coding: utf-8 -*-
"""T01 登录校验 —— CWE-89 SQL 注入

a    : /login  user/pass   字符串拼接（有洞）
b    : /signin username/password  字符串拼接（有洞 + 接口漂移）
safe : /login  user/pass   参数化查询（修复）
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
DB = None


def init_db():
    global DB
    DB = sqlite3.connect(":memory:", check_same_thread=False)
    DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, user TEXT, pass TEXT, note TEXT)")
    # admin 放在第一行, 使 "' OR '1'='1' --" 也能命中 flag
    DB.execute("INSERT INTO users VALUES (1,'admin','Adm!n-P@ssw0rd-9f3a','%s')" % FLAG)
    DB.execute("INSERT INTO users VALUES (2,'alice','alice123','welcome alice')")
    DB.execute("INSERT INTO users VALUES (3,'bob','bob456','welcome bob')")
    DB.commit()


VARIANT = {"a": ("a", "/login", "user", "pass"),
           "b": ("b", "/signin", "username", "password"),
           "safe": ("safe", "/login", "user", "pass")}


def build(variant):
    kind, ep, uk, pk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_POST(self):
            path, _ = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            f = self._form()
            u = self.first(f, uk)
            p = self.first(f, pk)
            try:
                if fixed:
                    cur = DB.execute(
                        "SELECT note FROM users WHERE user=? AND pass=?", (u, p))
                else:
                    cur = DB.execute(
                        "SELECT note FROM users WHERE user='%s' AND pass='%s'" % (u, p))
                row = cur.fetchone()
            except Exception as e:
                return self.reply(500, "db error: %s" % e)
            if row is None:
                return self.reply(401, "denied")
            note = row[0]
            if fixed:
                # 修复版: 任何登录成功都只回通用欢迎, 绝不含 flag
                # (flag 仅作为 SQLi 绕过后的奖励在漏洞版返回)
                return self.reply(200, "welcome %s" % u)
            if FLAG in note:
                return self.reply(200, "welcome admin\n%s" % FLAG)
            return self.reply(200, note)

        def do_GET(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    init_db()
    run(build)
