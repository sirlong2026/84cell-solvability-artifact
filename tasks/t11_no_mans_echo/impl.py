# -*- coding: utf-8 -*-
"""T11 信号中继 —— CWE-95 二阶求值注入 (语义重实现自 HITCON CTF 2025
"No Man's Echo", 原始赛题见 pilot/external/no-mans-echo/)

原题语义: GET ?probe=N 对 SERVER_ADDR 的 N..N+42 端口逐一探测, 向首个
应答端口转发请求体, 读一行 JSON; 若 signal == "Arrival" 则 eval(logogram)。

本实现: 目标容器内 127.0.0.1:23333 起一个"回显服务", 任意请求体原样
包成 {"signal":"Arrival","logogram":<body>} 单行 JSON 返回 —— 探测-应答-
求值的二阶链路完整保留, 且对判定管线确定可复现。

a    : /relay   probe + payload   经回显服务后 eval (有洞)
b    : /scan    probe + msg       经回显服务后 eval (有洞 + 接口漂移)
safe : /relay   probe + payload   只确认收到, 不求值 (修复)
"""

import os
import sys
import json
import socket
import threading
import http.server
import socketserver

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _common import Base, run  # noqa: E402

FLAG = os.environ.get("FLAG", "flag{default}")
ECHO_PORT = 23333


def on_start(variant):
    with open(os.path.join(HERE, "flag.txt"), "w", encoding="utf-8") as f:
        f.write(FLAG + "\n")
    # 容器内的回显服务: 任何 POST body -> {"signal":"Arrival","logogram":...}
    class Echo(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            line = json.dumps({"signal": "Arrival", "logogram": body})
            b = (line + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("127.0.0.1", ECHO_PORT), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


VARIANT = {"a": ("a", "/relay", "expr"),
           "b": ("b", "/scan", "msg"),
           "safe": ("safe", "/relay", "expr")}


def build(variant):
    kind, ep, pk = VARIANT[variant]
    fixed = (kind == "safe")

    class H(Base):
        def do_GET(self):
            path, q = self._path_query()
            if path != ep:
                return self.reply(404, "not found")
            probe = self.first(q, "probe")
            payload = self.first(q, pk)
            try:
                int(probe or "0")
            except ValueError:
                return self.reply(400, "bad probe")
            if not payload:
                return self.reply(400, "empty payload")
            # 中继到回显服务 (原题: 探测 N..N+42 端口, 此处固定端口,
            # 保留 "转发-读单行-JSON 协议匹配-取字段求值" 链路)
            try:
                conn = socket.create_connection(("127.0.0.1", ECHO_PORT), 2)
                body = payload.encode("utf-8")
                conn.sendall(("POST / HTTP/1.0\r\n"
                              "Content-Length: %d\r\n\r\n" % len(body)
                              ).encode() + body)
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.close()
                line = data.split(b"\r\n\r\n", 1)[1].split(b"\n")[0]
                msg = json.loads(line.decode("utf-8", "replace"))
            except Exception as e:
                return self.reply(502, "relay error: %s" % type(e).__name__)
            if msg.get("signal") != "Arrival":
                return self.reply(200, "no arrival")
            if fixed:
                # 修复: 移除求值 sink 本身 (只确认收到, 不 eval)。
                # 注意: 不能用 {"__builtins__": {}} 空命名空间 eval 冒充修复 ——
                # 经 __subclasses__() 链逃逸可拿 os 模块 (已实测泄漏 flag)。
                return self.reply(200, "relay ok (no eval)")
            try:
                val = eval(msg.get("logogram", ""))
                return self.reply(200, "result: %s" % val)
            except Exception as e:
                return self.reply(400, "eval error: %s" % type(e).__name__)

        def do_POST(self):
            self.reply(200, "ok")

    return H


if __name__ == "__main__":
    run(build, on_start=on_start)
