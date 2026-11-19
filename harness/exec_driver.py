# -*- coding: utf-8 -*-
"""
Agent 脚本执行器 (在 bench_net 内部网络的驱动容器内运行)

职责边界 (重要):
    本文件只做一件事 —— 执行 /drv/attempt.py 并回收输出。
    它不判断漏洞类型, 不判定成功, 不做任何安全语义解释。
    flag 是否出现由宿主 bench.py 在回收输出后判定 (判据集中一处, 避免双判据漂移)。

设计约束:
    - 驱动容器与靶机同处 internal 网络, 无外网出口: agent 生成的脚本无法外连,
      也无法回连攻击者机器。执行是隔离的。
    - 只用 Python 标准库执行, 不安装任何包。
    - 超时/输出长度双上限, 防止 agent 脚本死循环或刷爆日志。

输出约定: 最后一行 RESULT_EXEC_JSON:{...}
"""

import os
import sys
import json
import subprocess

TIMEOUT = int(os.environ.get("EXEC_TIMEOUT", "25"))
MAX_OUT = int(os.environ.get("MAX_OUT", "8000"))
PY = sys.executable or "python3"


def main():
    # 驱动容器复用后每轮覆盖同一路径; 路径可由 ATTEMPT_PATH 覆盖, 便于兼容
    # 预烘焙镜像(含 /drv/)与回退镜像(无 /drv/)两种布局。
    path = os.environ.get("ATTEMPT_PATH") or "/drv/attempt.py"
    if not os.path.isfile(path):
        print("RESULT_EXEC_JSON:" + json.dumps(
            {"ok": 0, "kind": "no_script", "out": "", "err": "attempt.py 不存在",
             "rc": None, "timeout": 0}, ensure_ascii=False))
        return 0

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            src = f.read()
    except Exception as e:
        print("RESULT_EXEC_JSON:" + json.dumps(
            {"ok": 0, "kind": "read_err", "out": "", "err": str(e)[:120],
             "rc": None, "timeout": 0}, ensure_ascii=False))
        return 0

    timed_out = 0
    try:
        p = subprocess.run([PY, path], capture_output=True,
                           text=True, timeout=TIMEOUT)
        out, err, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        timed_out = 1
        # 超时时 partial output 仍然有价值 (agent 可能已经拿到 flag 只是没退出)
        out = (e.stdout or b"")
        err = (e.stderr or b"")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        rc = None
    except Exception as e:
        print("RESULT_EXEC_JSON:" + json.dumps(
            {"ok": 0, "kind": "exec_err", "out": "", "err": str(e)[:120],
             "rc": None, "timeout": 0}, ensure_ascii=False))
        return 0

    # 语法/运行时错误归为一类: 用于统计 agent 的"可执行性"失败率
    kind = "ok"
    if rc not in (0, None):
        kind = "runtime_error"
    elif timed_out:
        kind = "timeout"

    print("RESULT_EXEC_JSON:" + json.dumps({
        "ok": 1 if kind == "ok" else 0,
        "kind": kind,
        "out": out[:MAX_OUT],
        "err": err[:MAX_OUT],
        "rc": rc,
        "timeout": timed_out,
        "src_len": len(src),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
