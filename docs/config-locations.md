# Config file locations

## Hook settings

| Harness | Global / user | Project |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | `.claude/settings.json` |
| OpenCode | `~/.config/opencode/opencode.json` | `./opencode.json` |
| Cursor | `~/.cursor/hooks.json` | `.cursor/hooks.json` |
| Copilot CLI | — (not supported) | `.github/hooks/PreToolUse.json` |
| Codex CLI | `~/.codex/hooks.json` | `.codex/hooks.json` |
| Gemini CLI | `~/.gemini/settings.json` | `.gemini/settings.json` |

## MCP server config

| Harness | Global / user | Project |
|---|---|---|
| Claude Code | `~/.claude.json` | `./.mcp.json` |
| OpenCode | `~/.config/opencode/opencode.json` | `./opencode.json` |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| Copilot CLI | `~/.copilot/mcp-config.json` | `./.mcp.json` |
| Codex CLI | `~/.codex/config.toml` | `.codex/config.toml` |
| Gemini CLI | `~/.gemini/settings.json` | `.gemini/settings.json` |

OpenCode and Gemini CLI store both hooks and MCP servers in the same file. Claude Code, Cursor, and Copilot CLI use separate files for each. Codex CLI uses a TOML config file for MCP servers.
