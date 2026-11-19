#!/bin/bash
# Multi-model replication of the 84-cell matrix (batch of 19 November 2026).
# Runs the same design on two further models so that the information-level
# contrast can be checked against a change of model. The fourth model tried in
# this batch was abandoned (endpoint timeouts, invalid records) and is not
# reported.
#
# Credentials come from the environment; nothing is stored in this file.
#   export DEEPSEEK_API_KEY=...  ALIYUN_API_KEY=...  AMD_API_KEY=...
set -u
cd "$(dirname "$0")"

for model in kimi_k31_pro amd_glm53_flash; do
  for lv in L1 L0; do
    echo "================================================================"
    echo "=== RUN $model / $lv  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "================================================================"
    python run_matrix.py --level "$lv" --model "$model" --tag "${model}_${lv}_1119" --k 1 2>&1 | tail -60
    echo "--- done $model $lv  $(date '+%H:%M:%S') ---"
  done
done
echo "ALL RUNS DONE $(date '+%Y-%m-%d %H:%M:%S')"
