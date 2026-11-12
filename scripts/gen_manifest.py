"""根据本地配置目录生成可信清单 manifest.json（仅标准库）。

被监视目录里的文件合法变更后，用本脚本重新生成清单并重启服务，
即完成一次"配置替换 + 清单更新"的正规发布流程。

用法：
    python3 -I scripts/gen_manifest.py \
        --root deploy/config \
        --directory /etc/integrity-demo \
        --output deploy/manifest.json

--root       宿主机上的配置目录（计算摘要用）
--directory  监测运行时看到的目录路径（写入清单，容器内路径）
--output     清单输出路径
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

MAX_FILES = 100
MAX_FILE_SIZE = 1 << 20


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成配置目录完整性清单（文件名 -> SHA-256）")
    parser.add_argument("--root", required=True, help="宿主机上的配置目录")
    parser.add_argument("--directory", required=True, help="监测运行时看到的目录绝对路径（写入清单）")
    parser.add_argument("--output", required=True, help="清单输出路径")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.root):
        print(f"错误：{args.root} 不是目录", file=sys.stderr)
        return 2
    if not args.directory.startswith("/"):
        print(f"错误：--directory 必须是绝对路径，收到 {args.directory!r}", file=sys.stderr)
        return 2

    files: dict[str, str] = {}
    skipped: list[str] = []
    with os.scandir(args.root) as it:
        for entry in sorted(it, key=lambda e: e.name):
            if not entry.is_file(follow_symlinks=False):
                skipped.append(entry.name)
                continue
            st = entry.stat(follow_symlinks=False)
            if st.st_size > MAX_FILE_SIZE:
                print(f"错误：{entry.name} 大小 {st.st_size} 超过 1MiB 上限", file=sys.stderr)
                return 2
            digest = hashlib.sha256()
            with open(entry.path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 16), b""):
                    digest.update(chunk)
            files[entry.name] = digest.hexdigest()

    if len(files) > MAX_FILES:
        print(f"错误：普通文件数量 {len(files)} 超过上限 {MAX_FILES}", file=sys.stderr)
        return 2
    for name in skipped:
        print(f"警告：跳过非普通文件 {name!r}（监测只覆盖单层普通文件）", file=sys.stderr)

    manifest = {"directory": args.directory, "files": files}
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"已生成清单 {args.output}：目录 {args.directory}，{len(files)} 个文件")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
