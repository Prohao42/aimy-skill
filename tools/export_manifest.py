"""从运行时解析器导出可再生命令清单 tools.json。

用法:
    python -m tools.export_manifest [--out data/tools.json]

CLI 与 MCP 运行时直接共用 argparse 定义；本文件是供文档生成和其他 Agent
集成使用的派生产物。修改命令后必须重新导出，测试会检查产物是否漂移。
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
