# Config file locations

## Hook settings

| Harness | Global / user | Project |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | `.claude/settings.json` |
| OpenCode | `~/.config/opencode/opencode.json` | `./opencode.json` |
| Copilot CLI | — (not supported) | `.github/hooks/PreToolUse.json` |

## MCP server config

| Harness | Global / user | Project |
|---|---|---|
| Claude Code | `~/.claude.json` | `./.mcp.json` |
| OpenCode | `~/.config/opencode/opencode.json` | `./opencode.json` |
| Copilot CLI | `~/.copilot/mcp-config.json` | `./.mcp.json` |

OpenCode stores both hooks and MCP servers in the same file. Claude Code and Copilot CLI use separate files for each.
