# -*- coding: utf-8 -*-
"""T12 留言板 —— CWE-89 受限 SQL 注入 (语义重实现自 HITCON CTF 2025
"Pholyglot!", 原始赛题见 pilot/external/pholyglot/)

原题语义: GET ?msg (<=30 字符) 被字符串格式化进 SQLite 的
CREATE TABLE / INSERT 语句 —— 输入直接成为 SQL 的一部分, 且有长度硬约束。

本实现: 留言查询接口, user/pass 拼接进 SQL (有洞), 且参数长度 >30
一律拒绝 (保留原题签名约束)。官方注入 payload 均在 30 字符内, 约束
不影响可达性, 只影响"能否塞长 payload"这一维度。

a    : /note  user/pass   字符串拼接 + 30 字符硬约束 (有洞)
b    : /memo  u/p         字符串拼接 + 30 字符硬约束 (有洞 + 接口漂移)
safe : /note  user/pass   参数化查询 (修复)
"""

import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
MAX_LEN = 30          # 原题签名: strlen($msg) <= 30
DB = None


def init_db():
    global DB
    DB = sqlite3.connect(":memory:", check_same_thread=False)
    DB.execute("CREATE TABLE board (id INTEGER PRIMARY KEY, "
               "user TEXT, pass TEXT, note TEXT)")
    DB.execute("INSERT INTO board VALUES (1,'admin','Adm!n-P@ss-7c2e','%s')"
               % FLAG)
    DB.execute("INSERT INTO board VALUES (2,'alice','alice123','note from alice')")
    DB.execute("INSERT INTO board VALUES (3,'bob','bob456','note from bob')")
    DB.commit()


def on_start(variant):
    init_db()


VARIANT = {"a": ("a", "/note", "user", "pass"),
           "b": ("b", "/memo", "u", "p"),
           "safe": ("safe", "/note", "user", "pass")}


def build(variant):
    kind, ep, uk, pk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_POST(self):
            path, _ = self._path_query()
            form = self._form()
            if path != ep:
                return self.reply(404, "not found")
            user = self.first(form, uk)
            pwd = self.first(form, pk)
            if len(user) > MAX_LEN or len(pwd) > MAX_LEN:
                return self.reply(400, "payload too long")
            try:
                if fixed:
                    cur = DB.execute(
                        "SELECT note FROM board WHERE user=? AND pass=?",
                        (user, pwd))
                else:
                    # 有洞: 字符串拼接 (原题: sprintf 进 CREATE/INSERT)
                    cur = DB.execute(
                        "SELECT note FROM board WHERE user='%s' AND pass='%s'"
                        % (user, pwd))
                row = cur.fetchone()
                if row:
                    if fixed:
                        # 修复版: 绝不回含 flag 的 note
                        # (flag 仅作为 SQLi 绕过后的奖励在漏洞版返回)
                        return self.reply(200, "message: ok")
                    return self.reply(200, "message: %s" % row[0])
                return self.reply(404, "no message")
            except sqlite3.Error as e:
                return self.reply(500, "sql error: %s" % type(e).__name__)

        def do_GET(self):
            path, _ = self._path_query()
            if path == ep:
                return self.reply(405, "use POST")
            return self.reply(404, "not found")

    return H


if __name__ == "__main__":
    run(build, on_start=on_start)
