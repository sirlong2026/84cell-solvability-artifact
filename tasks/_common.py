# -*- coding: utf-8 -*-
"""被测实现的公共底座: 参数解析 / 响应 / 端口上报"""

import os
import argparse
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Base(BaseHTTPRequestHandler):
    """所有题目实现继承此类; do_GET / do_POST 由子类实现"""

    def _path_query(self):
        u = urllib.parse.urlparse(self.path)
        return u.path, urllib.parse.parse_qs(u.query)

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return urllib.parse.parse_qs(raw)

    @staticmethod
    def first(d, key, default=""):
        v = d.get(key)
        if v:
            return v[0]
        return default

    def reply(self, code, text, ctype="text/plain; charset=utf-8"):
        b = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        try:
            self.wfile.write(b)
        except Exception:
            pass

    def log_message(self, *a):
        pass


# 根路径引导页：按题型渲染贴合的练习界面（而非统一的空请求器）。
#
# 设计要点（勿轻易改动）：
# 1. 每题按真实交互形态给对应控件：登录表单 / 单参数输入 / 直接展示，
#    而不是让所有题共用一个空请求框——14 题解法完全不同，通用表单等于把难度推给学生。
# 2. 🔴 遵循信息层级：L1（给出接口名）才显示方法/路径/参数名；L0（只给 URL）一律不显示，
#    学生自行探测。信息层级落差（52.4% vs 4.8%）是本作品的核心评测点，靶机页泄露即毁掉实验设计。
# 3. 🔴 只给"这是干什么的接口"的功能描述，**不给 payload、不给 flag、不给答案**。
# 4. 全部请求发往同源（当前靶机自身），不跨域。漏洞逻辑一行不动（本文件只拦截根路径）。
#
# 题目标识：优先读环境变量 TASK_ID，否则按端口推（端口 = 18000 + 题号，与部署约定一致）。

import html as _html
import json as _json
import os as _os


def _task_id(port):
    tid = _os.environ.get("TASK_ID", "").strip()
    if tid:
        return tid
    n = port - 18000
    if 1 <= n <= 14:
        return "t%02d" % n
    # 兜底：从调用栈里找实现文件（tasks/t01_sqli/impl.py）所在目录识别题号，
    # 防端口非标准时认不出题号。注意不能用本文件 __file__——_common.py 位于 tasks/ 根，
    # 永远拿不到题号目录；也不能只看栈顶（_practice_page 是中间层，不是 impl）。
    try:
        import sys as _sys
        import re as _re
        f = _sys._getframe(1)
        while f is not None:
            d = _os.path.basename(_os.path.dirname(_os.path.abspath(f.f_code.co_filename)))
            m = _re.match(r"(t0[1-9]|t1[0-4])", d)
            if m:
                return m.group(1)
            f = f.f_back
    except Exception:
        pass
    return ""


def _info_level():
    """L1 = 给出接口名与参数；L0 = 只给访问地址。默认 L1（首次试跑全 L1）。"""
    for k in ("INFO_LEVEL", "GROUP_LEVEL", "LEVEL"):
        v = _os.environ.get(k, "").strip().upper()
        if v in ("L0", "L1"):
            return v
    return "L1"


# 每题档案：kind=form（账号密码表单）/ single（单参数）/ show（直接展示，自身无参数）
# title/blurb 只描述接口用途，不含任何利用线索。
_TASK_UI = {
    "t01": dict(kind="form", title="登录校验", cwe="CWE-89 SQL 注入",
                blurb="这是登录校验接口。尝试以合法身份登录。",
                method="POST", endpoint="/login",
                fields=[("user", "用户名"), ("pass", "密码")], submit="登录"),
    "t02": dict(kind="single", title="文件下载", cwe="CWE-22 路径穿越",
                blurb="这是文件下载接口，按给出的文件名返回文件内容。",
                method="GET", endpoint="/download",
                fields=[("file", "文件名")], submit="下载"),
    "t03": dict(kind="single", title="模板渲染", cwe="CWE-94 服务端模板注入",
                blurb="这是模板渲染接口，输入内容会被当作模板渲染。",
                method="GET", endpoint="/render",
                fields=[("name", "模板内容")], submit="渲染"),
    "t04": dict(kind="single", title="配置装载", cwe="CWE-502 不安全反序列化",
                blurb="这是配置装载接口，提交一段配置数据完成装载。",
                method="POST", endpoint="/load",
                fields=[("data", "配置数据")], submit="装载"),
    "t05": dict(kind="single", title="主机探测", cwe="CWE-78 命令注入",
                blurb="这是主机探测接口，填入主机名查看连通性。",
                method="GET", endpoint="/ping",
                fields=[("host", "主机")], submit="探测"),
    "t06": dict(kind="single", title="远端抓取", cwe="CWE-918 服务端请求伪造",
                blurb="这是远端抓取接口，填入 URL 由服务端发起请求。",
                method="GET", endpoint="/fetch",
                fields=[("url", "URL")], submit="抓取"),
    "t07": dict(kind="single", title="密码重置", cwe="CWE-338 弱随机令牌",
                blurb="这是密码重置接口，按指定动作执行重置流程。",
                method="GET", endpoint="/reset",
                fields=[("action", "动作")], submit="执行"),
    "t08": dict(kind="single", title="资料查询", cwe="CWE-639 越权访问",
                blurb="这是个人资料查询接口，按编号返回对应用户资料。",
                method="GET", endpoint="/profile",
                fields=[("id", "用户编号")], submit="查询"),
    "t09": dict(kind="show", title="健康检查", cwe="CWE-200 信息泄露",
                blurb="这是服务健康检查端点，直接访问即可查看其返回内容。",
                method="GET", endpoint="/debug", fields=[], submit="访问"),
    "t10": dict(kind="single", title="在线计算器", cwe="CWE-95 表达式注入",
                blurb="这是在线计算器接口，填入算术表达式查看计算结果。",
                method="GET", endpoint="/calc",
                fields=[("expr", "表达式")], submit="计算"),
    "t11": dict(kind="single", title="信号中继", cwe="CWE-95 表达式注入",
                blurb="这是信号中继接口，填入表达式由服务端转发处理。",
                method="GET", endpoint="/relay",
                fields=[("expr", "表达式")], submit="转发"),
    "t12": dict(kind="form", title="留言板登录", cwe="CWE-89 受限 SQL 注入",
                blurb="这是留言板登录接口。尝试以合法身份登录。",
                method="POST", endpoint="/note",
                fields=[("user", "用户名"), ("pass", "密码")], submit="登录"),
    "t13": dict(kind="single", title="通知服务", cwe="CWE-78 命令注入",
                blurb="这是通知服务接口，填入目标主机名发送通知。",
                method="GET", endpoint="/notify",
                fields=[("host", "主机")], submit="发送"),
    "t14": dict(kind="single", title="卡面渲染", cwe="CWE-918 服务端请求伪造",
                blurb="这是卡面渲染接口，填入资源 URL 由服务端取回并渲染。",
                method="GET", endpoint="/render",
                fields=[("url", "URL")], submit="渲染"),
}

_CSS = """*{box-sizing:border-box}
body{margin:0;background:#0b1413;color:#e6f0ee;font-family:system-ui,'Microsoft YaHei',sans-serif;padding:22px;line-height:1.65}
.wrap{max-width:760px;margin:0 auto}
h1{font-size:19px;color:#3fd0c9;margin:0 0 6px}
.cwe{display:inline-block;background:#132522;color:#7fe3da;border-radius:999px;padding:2px 10px;font-size:12px;margin-left:8px}
.meta{color:#9fb4b0;font-size:12.5px;margin-bottom:16px}
.blurb{background:#111d1b;border:1px solid #1e2f2c;border-left:3px solid #3fd0c9;border-radius:10px;padding:12px 14px;margin-bottom:16px;font-size:13.5px}
.ep{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:#7fe3da;margin-bottom:12px}
label{display:block;font-size:12.5px;color:#9fb4b0;margin:10px 0 4px}
input{width:100%;background:#0a1513;color:#e6f0ee;border:1px solid #1e2f2c;border-radius:8px;padding:10px 12px;font-size:13.5px;font-family:ui-monospace,Consolas,monospace}
button{margin-top:14px;background:#3fd0c9;color:#04211d;border:0;border-radius:8px;padding:10px 22px;font-size:14px;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.08)}
pre{background:#08110f;border:1px solid #1e2f2c;border-radius:8px;padding:12px;min-height:110px;max-height:320px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:#d8ece8}
.tip{color:#9fb4b0;font-size:12.5px;margin-top:14px}"""


def _esc(s):
    return _html.escape(str(s), quote=True)


def _guide_page(port, variant, task_id, level):
    prof = _TASK_UI.get(task_id)
    head = ("<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>实训靶机 · 端口 %d</title><style>%s</style></head><body><div class=\"wrap\">"
            % (port, _CSS))
    foot = "</div></body></html>"

    if not prof:
        # 未知题号：只给出在线确认，不展示任何接口信息
        return head + (
            "<h1>靶机在线</h1>"
            "<div class=\"meta\">端口 %d · 变体 %s · 校内 openEuler 靶机（仅内网）</div>"
            "<div class=\"blurb\">本题为接口型题目，无可视化界面。请回到学生答题页按题面信息发起请求。</div>"
            "<p class=\"tip\">得到的 flag 请回学生答题页提交。</p>%s"
            % (port, _esc(variant), foot))

    title = _esc(prof["title"])
    cwe = _esc(prof["cwe"])
    blurb = _esc(prof["blurb"])

    # 🔴 L0：只给访问地址。不显示方法/路径/参数名，**也不显示接口用途描述**
    # （blurb 本身会指向解法方向，如"文件下载…文件名"等于给 L0 递了提示），
    # 学生须完全自行探测。信息层级落差是核心评测点，此处一律不泄露。
    if level != "L1":
        return head + (
            "<h1>%s</h1><span class=\"cwe\">%s</span>"
            "<div class=\"meta\">端口 %d · 变体 %s · 访问地址 <span class=\"ep\">http://本机:%d/</span></div>"
            "<div class=\"blurb\">本题不提供接口名、参数与用途说明，请在下方地址自行探测。</div>"
            "<p class=\"tip\">得到的 flag 请回学生答题页提交。</p>%s"
            % (title, cwe, port, _esc(variant), port, foot))

    method = _esc(prof["method"])
    endpoint = _esc(prof["endpoint"])
    kind = prof["kind"]

    ep_line = ("<div class=\"ep\">请求：%s %s</div>" % (method, endpoint))
    inputs = "".join(
        "<label>%s</label><input id=\"f%d\" autocomplete=\"off\">"
        % (_esc(lbl), i) for i, (_n, lbl) in enumerate(prof["fields"]))

    if kind == "show":
        body_form = ("<button id=\"go\">%s</button>"
                     % _esc(prof["submit"]))
    else:
        body_form = inputs + ("<button id=\"go\">%s</button>" % _esc(prof["submit"]))

    js = """
<script>
(function(){
  var m=%(M)s, ep=%(EP)s, go=document.getElementById('go'),
      out=document.getElementById('o');
  function send(){
    var ps=document.querySelectorAll('input');
    if(m==='POST'){
      var fd=new URLSearchParams();
      ps.forEach(function(el,i){ fd.append(%(NAMES)s[i], el.value); });
      fetch(ep,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd.toString()})
        .then(r=>r.text().then(t=>show(r.status,t)))
        .catch(e=>out.textContent='请求失败：'+e);
    }else if(ps.length){
      var q=new URLSearchParams();
      ps.forEach(function(el,i){ q.append(%(NAMES)s[i], el.value); });
      fetch(ep+'?'+q.toString()).then(r=>r.text().then(t=>show(r.status,t)))
        .catch(e=>out.textContent='请求失败：'+e);
    }else{
      fetch(ep).then(r=>r.text().then(t=>show(r.status,t)))
        .catch(e=>out.textContent='请求失败：'+e);
    }
  }
  function show(code,t){ out.textContent='[HTTP '+code+']\\n'+(t.length?t:'(空响应体)'); }
  go.addEventListener('click',send);
})();
</script>
""" % {"M": _json.dumps(method), "EP": _json.dumps(endpoint),
       "NAMES": _json.dumps([n for n, _ in prof["fields"]])}

    return head + (
        "<h1>%s</h1><span class=\"cwe\">%s</span>"
        "<div class=\"meta\">端口 %d · 变体 %s · 访问地址 <span class=\"ep\">http://本机:%d/</span></div>"
        "<div class=\"blurb\">%s</div>%s%s<pre id=\"o\">尚未提交。</pre>"
        "<p class=\"tip\">本题面给出接口与参数（L1 层级）。请自行构造请求验证；"
        "得到的 flag 回学生答题页提交。注意：真实靶机请勿扫描无关端口或破坏环境。</p>%s%s"
        % (title, cwe, port, _esc(variant), port, blurb, ep_line, body_form, js, foot))


def _practice_page(port, variant):
    return _guide_page(port, variant, _task_id(port), _info_level())


def run(build_handler, on_start=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", default="a")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    if on_start:
        on_start(args.variant)
    H = build_handler(args.variant)

    # 根路径「靶机练习台」：学生端「打开靶机」按钮指向 host:port/，
    # 多数靶机只实现了真实漏洞接口（如 /download），根路径原本 404。
    # 此处统一在公共底座拦截根路径，返回一个同源 HTTP 请求器页面，
    # 既不改动任何漏洞逻辑，也让学生端能真正构造请求、看到响应。
    landing = _practice_page(args.port, args.variant)

    class _Landing(H):
        def _is_root(self):
            p, _ = self._path_query()
            return p == "/" or p == ""

        def do_GET(self):
            if self._is_root():
                self.reply(200, landing, ctype="text/html; charset=utf-8")
                return
            return H.do_GET(self)

        def do_POST(self):
            if self._is_root():
                self.reply(200, landing, ctype="text/html; charset=utf-8")
                return
            if hasattr(H, "do_POST"):
                return H.do_POST(self)
            self.reply(404, "not found")

    srv = ThreadingHTTPServer(("0.0.0.0", args.port), _Landing)
    port = srv.server_address[1]
    print("PORT=%d" % port, flush=True)
    sys_argv_guard = None
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return srv
