# -*- coding: utf-8 -*-
"""
判定驱动 (在 bench_net 内部网络中运行)

与目标容器同处内部网络, 通过容器别名 target:8080 访问被测服务。
所有功能测试与 exploit 在容器内执行, 宿主只读取结果 JSON。

输出约定: 最后一行 RESULT_JSON:{...}
"""

import sys
import json
import os

sys.path.insert(0, "/drv")
import exploits                      # noqa: E402
from harness import run_functional   # noqa: E402


def main():
    with open("/drv/spec.json", encoding="utf-8") as f:
        spec = json.load(f)
    base = os.environ["TARGET_URL"]

    try:
        f_ok, f_detail, f_p, f_t = run_functional(base, spec)
    except Exception as e:
        f_ok, f_detail, f_p, f_t = "", "driver_err:%s" % str(e)[:80], 0, 0
    try:
        e_base, ev_b = exploits.run_exploit(base, spec, "base", spec["flag"])
    except Exception as e:
        e_base, ev_b = 0, "driver_err:%s" % str(e)[:80]
    try:
        e_adap, ev_a = exploits.run_exploit(base, spec, "adaptive", spec["flag"])
    except Exception as e:
        e_adap, ev_a = 0, "driver_err:%s" % str(e)[:80]

    out = {
        "functional_pass": int(f_ok) if f_ok != "" else "",
        "func_detail": f_detail,
        "func_score": "%d/%d" % (f_p, f_t),
        "exploit_base": int(e_base),
        "exploit_adaptive": int(e_adap),
        "evidence": (ev_a if e_adap else ev_b)[:160],
    }
    print("RESULT_JSON:" + json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
