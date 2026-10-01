<!-- pane-agent-context:start -->
## Pane

This repository is used with [Pane](https://runpane.com). Drive it with the CLI or the `pane` MCP server.

CLI: `npm i -g runpane` (or `npx --yes runpane@latest`), then `runpane doctor --json`. Full command reference: `runpane agent-context --json`.

MCP: packaged Pane registers a stdio server named `pane` with Claude Code and Codex. Check the connection with `claude mcp list` or `codex mcp list`. If tools are missing, add it in the agent's MCP settings: Claude Code `claude mcp add --scope user pane -- npx --yes runpane@latest mcp`; Codex (`~/.codex/config.toml`) table `[mcp_servers.pane]` with `command = "npx"` and `args = ["--yes", "runpane@latest", "mcp"]`; any other stdio client uses the same command and args.
<!-- pane-agent-context:end -->
