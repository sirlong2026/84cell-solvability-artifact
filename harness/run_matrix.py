# -*- coding: utf-8 -*-
"""
通用矩阵跑批驱动 —— 补跑 / 全量跑某一信息层级 (L0/L1/L2)

与 bench.py 的关系
-----------------
bench.py 的 --resume 按 run_id 去重, 而 run_id 不含 info_level,
导致跨层级(l1 vs l0)续跑会撞同名 ID、漏跑。本驱动改为按
(level, task_id, variant, k) 去重, 彻底规避该问题:
  - 补跑 L1: 只跑"文件中尚未出现过的 L1 组合", 不会重跑已有 run
  - 全量 L0: 文件中无 L0 组合, 跑满 14题 x 3变体 x k
  - daemon 挂死: ensure_daemon 等不到恢复就干净退出; 重跑本脚本自动跳过已完成项

用法
    export DEEPSEEK_API_KEY=sk-...
    python agent/run_matrix.py --level L1 --tag L1b --k 1
    python agent/run_matrix.py --level L0 --tag L0  --k 1
    python agent/run_matrix.py --level L2 --tag L2  --k 1 --thinking on
"""
import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench

MODELS = bench.MODELS
VARIANTS = ["a", "b", "safe"]


def done_level_set(model_key):
    """已完成的 (model_key, info_level, task_id, variant, k) 集合 (error 非空的不算)

    模型必须进去重键: 2026-09-27 前这里只有 (level,task,variant,k), 一旦换模型补跑,
    矩阵会把另一模型已有的组合当成"已跑过"而直接退出, 静默少跑一整层。
    """
    s = set()
    if not os.path.isfile(bench.RUNS_JSONL):
        return s
    for line in open(bench.RUNS_JSONL, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("error"):
            continue
        s.add((r.get("model_key"), r.get("info_level"), r.get("task_id"),
               r.get("variant"), r.get("k")))
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", choices=["L0", "L1", "L2"], default="L1")
    ap.add_argument("--tag", default="batch")
    ap.add_argument("--model", choices=sorted(MODELS), default=bench.DEFAULT_MODEL)
    ap.add_argument("--k", type=int, default=1)
    ap.add_argument("--thinking", choices=["off", "on"], default="off")
    ap.add_argument("--force", action="store_true",
                    help="忽略已完成记录, 按 tag 全量重跑 (默认只跑未出现过的组合)")
    ap.add_argument("--tasks", default="",
                    help="逗号分隔任务子集 (如 t01,t14); 空=全部 14 题 (冒烟/复核用)")
    args = ap.parse_args()

    tasks = bench.load_tasks()
    if args.tasks:
        want = [t.strip() for t in args.tasks.split(",") if t.strip()]
        tasks = {tid: tasks[tid] for tid in want if tid in tasks}
        missing = [t for t in want if t not in tasks]
        if missing:
            raise SystemExit("未知任务 id: %s" % missing)
    done = set() if args.force else done_level_set(args.model)

    plan = []
    for tid in sorted(tasks):
        for v in VARIANTS:
            for k in range(1, args.k + 1):
                if (args.model, args.level, tid, v, k) in done:
                    continue
                plan.append((tid, v, k))

    if not plan:
        print("[info] %s 层无待跑组合, 直接退出" % args.level)
        return 0

    print("[plan] %s 层待跑 %d 个组合 (tag=%s model=%s thinking=%s)"
          % (args.level, len(plan), args.tag, args.model, args.thinking))
    os.makedirs(bench.RESULTS, exist_ok=True)
    n = 0
    # DRIVER.start 前曾直接抛 RuntimeError 连累整个组合 (2026-09-27: daemon 半死态下
    # daemon_ok 偶尔通过但 docker rm -f 超时, 6 个组合全崩在此)。改为重试+等待。
    started = False
    for _attempt in range(3):
        try:
            bench.DRIVER.start()
            started = True
            break
        except Exception as e:
            sys.stderr.write("[warn] DRIVER.start 失败 (%s), 等待 daemon 后重试\n" % e)
            if not bench.ensure_daemon():
                break
    if not started:
        print("[abort] 驱动容器无法启动, 重跑本脚本即可续跑")
        return 0
    # SSRF 题 (t06/t14) 依赖 bench_net 上的 inner 服务; 不拉则恒 502。
    # 放在 DRIVER.start 成功之后: 此时 NET 已存在, 与 bench.main 同序。
    bench.start_inner_if_needed(tasks, sorted(tasks))
    try:
        with open(bench.RUNS_JSONL, "a", encoding="utf-8") as f:
            for tid, v, k in plan:
                if not bench.ensure_daemon():
                    print("\n[abort] dockerd 未恢复, 干净退出; "
                          "重跑本脚本即可续跑已完成项")
                    break
                try:
                    rec = bench.run_one(tasks[tid], v, args.model, k,
                                        args.level, tag=args.tag,
                                        thinking=args.thinking)
                except Exception as e:
                    # 单 run 崩溃不写行 (续跑自动补), 不连累矩阵
                    sys.stderr.write("[warn] run %s_%s 异常: %s, 跳过\n"
                                     % (tid, v, e))
                    continue
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                n += 1
                print("  [%s] %s_%s_k%d_%s solved=%d rounds=%d/%d tok=%d %.0fs%s"
                      % (rec["model_id"] or args.model, tid, v, k, args.tag,
                         rec["solved"], rec["rounds_used"], bench.MAX_ROUNDS,
                         rec["total_tokens"], rec["wall_s"],
                         ("  ERR:%s" % rec["error"]) if rec["error"] else ""))
    finally:
        bench.DRIVER.close()
        try:
            bench.sh(["docker", "rm", "-f", bench.TARGET_ALIAS], timeout=30)
        except Exception:
            pass
    print("\n完成 %d runs -> %s" % (n, bench.RUNS_JSONL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
