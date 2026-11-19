# 被测代码运行时镜像
#
# 设计约束:
#   1. 非 root 运行 (uid 10001), 降低生成代码提权影响
#   2. slim 基础镜像, 不含编译器与包管理器, 减少可利用面
#   3. /task 在运行时由 docker cp 注入, 不挂宿主目录 -> 宿主文件不会被生成代码改写
#   4. 不安装任何额外依赖, 保持与预实验相同的标准库口径

FROM python:3.13-slim

RUN useradd -m -u 10001 bench \
    && mkdir -p /task /work \
    && chown -R bench:bench /task /work

USER bench
WORKDIR /task

ENV PYTHONIOENCODING=utf-8 \
    PYTHONUNBUFFERED=1 \
    WORK_DIR=/work

EXPOSE 8080

# variant 由运行期覆盖; 端口固定 8080, 宿主侧随机映射
CMD ["python", "impl.py", "--variant", "a", "--port", "8080"]
