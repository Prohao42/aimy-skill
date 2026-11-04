"""aimy-skill MCP 接入层。

把 88 条 CLI 命令暴露为 MCP tools (stdio transport)，供任意 MCP 客户端接入。
包名用 aimy_mcp 而非 mcp，避免与官方 mcp SDK 包名冲突。
"""
