# MCP setup

`gate mcp` is a stdio JSON-RPC proxy that sits in front of an upstream MCP server. It forwards traffic verbatim except for `tools/call` responses, which pass through Gate 2 before reaching the model.

There are two ways to register it: convert existing MCP servers in bulk (`--wrap-mcp`), or register a single server manually (`--mcp`).

## Wrap existing MCP servers

`--wrap-mcp` reads the harness's MCP config and rewrites each entry so it points at `gate mcp <original-command>` instead of the original command. Dry-run by default; pass `--yes` to apply.

```bash
# Claude Code — wrap all servers in ~/.claude.json (dry-run)
gate init --wrap-mcp

# Claude Code — wrap all servers in ./.mcp.json (dry-run)
gate init --scope project --wrap-mcp

# Wrap only specific servers
gate init --wrap-mcp --servers postgres,github

# Apply
gate init --wrap-mcp --yes
gate init --wrap-mcp --servers postgres,github --yes
gate init --scope project --wrap-mcp --yes

# OpenCode
gate init --harness opencode --wrap-mcp --yes

# Copilot CLI — project-level .mcp.json (dry-run)
gate init --harness copilot-cli --scope project --wrap-mcp

# Copilot CLI — user-level ~/.copilot/mcp-config.json (dry-run)
gate init --harness copilot-cli --wrap-mcp
```

Already-proxied servers are skipped automatically, so re-running is safe.

## Register a single server

```bash
# Claude Code — user-level (~/.claude.json)
gate init --mcp postgres --mcp-cmd "uvx mcp-server-postgres"

# Claude Code — project-level (./.mcp.json)
gate init --scope project --mcp postgres --mcp-cmd "uvx mcp-server-postgres"

# OpenCode
gate init --harness opencode --mcp postgres --mcp-cmd "uvx mcp-server-postgres"

# Copilot CLI — user-level (~/.copilot/mcp-config.json)
gate init --harness copilot-cli --mcp postgres --mcp-cmd "uvx mcp-server-postgres"

# Copilot CLI — project-level (.mcp.json)
gate init --harness copilot-cli --scope project --mcp postgres --mcp-cmd "uvx mcp-server-postgres"
```

## Scope of redaction

Only `tools/call` responses are redacted. `resources/read`, `prompts/get`, and other MCP message types pass through without inspection. If your MCP server returns PII through those paths, the model will see it unredacted.

See [config-locations.md](config-locations.md) for the exact file each harness reads MCP server definitions from.
