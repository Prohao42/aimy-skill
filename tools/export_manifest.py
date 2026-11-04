"""导出单一事实源 tools.json: 从 COMMAND_SPECS + argparse 生成机器可读清单。

用法:
    python tools/export_manifest.py [--out data/tools.json]

生成的文件供 mcp/server.py、文档生成、OpenAI function 定义等共享，
改命令只改 COMMAND_SPECS / arg_parsers 一处，重新导出即全端同步。
"""

from __future__ import annotations

import argparse
import json

from tools.manifest import build_manifest


def main() -> None:
    p = argparse.ArgumentParser(description="导出 aimy-skill 工具清单 JSON")
    p.add_argument("--out", default="data/tools.json", help="输出路径")
    args = p.parse_args()

    manifest = build_manifest()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    n = len(manifest["commands"])
    print(
        "exported %d commands + %d global params -> %s"
        % (n, len(manifest["global_parameters"]), args.out)
    )


if __name__ == "__main__":
    main()
