"""Claude Code hooks integration for validating tool calls and results."""

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

from ward.config import Policy
from ward.logger import log_event, EVENT_BLOCK, EVENT_WARN, EVENT_DETECT
from ward.platform_utils import get_guard_dir, get_home_dir


# Hook script that gets installed into Claude Code
HOOK_SCRIPT = r'''#!/usr/bin/env python3
"""
Ward hook for Claude Code - validates tool calls for dangerous patterns.

This script is called by Claude Code before/after tool execution.
It receives tool call info on stdin as JSON and can block execution
by exiting with code 2.

Exit codes:
  0 - Allow the tool call
  2 - Block the tool call (Claude Code will not execute it)
"""

import json
import os
import re
import sys
from typing import Optional, Tuple

# Dangerous patterns to detect in Bash commands
DANGEROUS_PATTERNS = [
    # find -exec variants
    (r"find\s+.*\s+-(exec|execdir|ok|okdir)\s", "find with -exec can execute arbitrary commands"),

    # Shell -c execution
    (r"\b(sh|bash|zsh|dash)\s+-c\s", "shell -c executes arbitrary commands"),

    # Python/Node inline execution
    (r"\bpython[23]?\s+-c\s", "python -c executes arbitrary code"),
    (r"\bnode\s+(-e|--eval)\s", "node -e executes arbitrary code"),

    # tar checkpoint exploit
    (r"tar\s+.*--checkpoint-action", "tar checkpoint-action can execute commands"),

    # curl/wget pipe to shell
    (r"(curl|wget)[^|]*\|\s*(sh|bash|zsh|python|perl)", "piping download to interpreter is dangerous"),

    # Reverse shell patterns
    (r"/dev/tcp/", "potential reverse shell via /dev/tcp"),
    (r"\bnc\s+.*-e\s", "netcat with -e can spawn shells"),
    (r"mkfifo\s+.*(nc|netcat)", "potential reverse shell via named pipe"),

    # Base64 decode and execute
    (r"base64\s+(-d|--decode).*\|\s*(sh|bash|python|perl)", "base64 decode piped to interpreter"),

    # eval/exec patterns
    (r"\beval\s+.*\$", "eval with variable expansion is dangerous"),

    # Environment variable manipulation for injection
    (r"export\s+\w+\s*=.*\$\(", "environment variable set from command substitution"),

    # Dangerous file operations that could indicate exploitation
    (r">\s*/etc/", "writing to /etc is dangerous"),
    (r"chmod\s+[0-7]*[sS]", "setting setuid/setgid bits"),
    (r"chown\s+root", "changing ownership to root"),
]

# Patterns that indicate tool result manipulation/injection
RESULT_INJECTION_PATTERNS = [
    (r"<\s*/?tool_result", "potential tool result injection"),
    (r"<\s*/?function_result", "potential function result injection"),
    (r"<\s*/?antml:", "potential XML injection in results"),
    (r"^Human:\s*$", "potential conversation injection"),
    (r"^Assistant:\s*$", "potential conversation injection"),
]


def check_bash_command(command: str, enforce: bool = False) -> Tuple[bool, Optional[str]]:
    """Check a bash command for dangerous patterns."""
    for pattern, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return (False, reason) if enforce else (True, reason)
    return (True, None)


def check_tool_result(result: str) -> Tuple[bool, Optional[str]]:
    """Check tool result for injection attempts."""
    for pattern, reason in RESULT_INJECTION_PATTERNS:
        if re.search(pattern, result, re.IGNORECASE | re.MULTILINE):
            return (False, reason)
    return (True, None)


def validate_tool_call(tool_name: str, tool_input: dict, enforce: bool = False) -> Tuple[bool, Optional[str]]:
    """Validate a tool call before execution."""
    # Check Bash tool
    if tool_name.lower() == "bash":
        command = tool_input.get("command", "")
        return check_bash_command(command, enforce)

    # Check Write tool for suspicious content
    if tool_name.lower() == "write":
        content = tool_input.get("content", "")
        file_path = tool_input.get("file_path", "")
        if file_path.endswith((".sh", ".bash", ".zsh")):
            allow, reason = check_bash_command(content, enforce)
            if not allow:
                return (False, f"Writing dangerous script: {reason}")

    # Check Edit tool
    if tool_name.lower() == "edit":
        new_string = tool_input.get("new_string", "")
        file_path = tool_input.get("file_path", "")
        if file_path.endswith((".sh", ".bash", ".zsh")):
            allow, reason = check_bash_command(new_string, enforce)
            if not allow:
                return (False, f"Editing script with dangerous pattern: {reason}")

    return (True, None)


def log_to_ward(event_type: str, tool_name: str, blocked: bool, reason: str = None, details: dict = None):
    """Log event to ward's log file."""
    import datetime
    log_dir = os.path.expanduser("~/.ward/logs")
    os.makedirs(log_dir, exist_ok=True)

    event = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "source": "claude_code_hook",
        "tool_name": tool_name,
        "blocked": blocked,
        "reason": reason,
    }
    if details:
        event.update(details)

    log_file = os.path.join(log_dir, "hooks.jsonl")
    with open(log_file, "a") as f:
        f.write(json.dumps(event) + "\n")


def main():
    # Read hook input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)  # Invalid input, allow by default

    hook_type = input_data.get("hook_type", "")
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    tool_result = input_data.get("tool_result", "")

    # Check enforce mode
    enforce = os.environ.get("WARD_ENFORCE", "0") == "1"

    # Pre-tool validation
    if hook_type == "PreToolUse":
        allow, reason = validate_tool_call(tool_name, tool_input, enforce)

        if not allow:
            log_to_ward("block", tool_name, True, reason, {"input": tool_input})
            print(f"[ward] BLOCKED: {reason}", file=sys.stderr)
            sys.exit(2)  # Exit code 2 = block
        elif reason:
            log_to_ward("warn", tool_name, False, reason, {"input": tool_input})
            print(f"[ward] WARNING: {reason}", file=sys.stderr)

    # Post-tool validation (check results for injection)
    elif hook_type == "PostToolUse":
        if tool_result:
            safe, reason = check_tool_result(str(tool_result))
            if not safe:
                log_to_ward("detect", tool_name, False, reason, {"result_preview": str(tool_result)[:500]})
                print(f"[ward] ALERT: Suspicious tool result - {reason}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
'''


def get_hooks_dir() -> Path:
    """Get the directory for ward hook scripts."""
    return get_guard_dir() / "hooks"


def get_claude_settings_path() -> Path:
    """Get the Claude Code settings file path."""
    return get_home_dir() / ".claude" / "settings.json"


def install_hook_script() -> Path:
    """Install the ward hook script."""
    hooks_dir = get_hooks_dir()
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / "validate_tool.py"
    hook_path.write_text(HOOK_SCRIPT)
    hook_path.chmod(0o755)

    return hook_path


def get_current_claude_settings() -> dict:
    """Load current Claude Code settings."""
    settings_path = get_claude_settings_path()

    if not settings_path.exists():
        return {}

    try:
        return json.loads(settings_path.read_text())
    except (json.JSONDecodeError, IOError):
        return {}


def save_claude_settings(settings: dict) -> None:
    """Save Claude Code settings."""
    settings_path = get_claude_settings_path()
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    settings_path.write_text(json.dumps(settings, indent=2))


def install_claude_hooks(enforce: bool = False) -> dict:
    """
    Install ward hooks into Claude Code settings.

    Args:
        enforce: If True, hooks will block dangerous tool calls

    Returns:
        dict with installation results
    """
    result = {
        "success": False,
        "hook_path": None,
        "settings_modified": False,
        "previous_hooks": None,
        "errors": [],
    }

    # Install the hook script
    try:
        hook_path = install_hook_script()
        result["hook_path"] = str(hook_path)
    except Exception as e:
        result["errors"].append(f"Failed to install hook script: {e}")
        return result

    # Build the hook command
    env_prefix = "WARD_ENFORCE=1 " if enforce else ""
    hook_command = f"{env_prefix}python3 {hook_path}"

    # Load current settings
    settings = get_current_claude_settings()

    # Store previous hooks for backup
    result["previous_hooks"] = settings.get("hooks", {})

    # Add ward hooks
    if "hooks" not in settings:
        settings["hooks"] = {}

    # Install PreToolUse hook for Bash
    settings["hooks"]["PreToolUse"] = [
        {
            "matcher": "Bash",
            "hooks": [hook_command]
        },
        {
            "matcher": "Write",
            "hooks": [hook_command]
        },
        {
            "matcher": "Edit",
            "hooks": [hook_command]
        }
    ]

    # Install PostToolUse hook to check results
    settings["hooks"]["PostToolUse"] = [
        {
            "matcher": ".*",
            "hooks": [hook_command]
        }
    ]

    # Save settings
    try:
        save_claude_settings(settings)
        result["settings_modified"] = True
        result["success"] = True
    except Exception as e:
        result["errors"].append(f"Failed to save Claude settings: {e}")

    return result


def remove_claude_hooks() -> dict:
    """
    Remove ward hooks from Claude Code settings.

    Returns:
        dict with removal results
    """
    result = {
        "success": False,
        "settings_modified": False,
        "errors": [],
    }

    settings = get_current_claude_settings()

    if "hooks" not in settings:
        result["success"] = True
        return result

    # Remove ward hooks (hooks that reference our script)
    ward_hook_dir = str(get_hooks_dir())
    modified = False

    for hook_type in ["PreToolUse", "PostToolUse"]:
        if hook_type in settings["hooks"]:
            original_hooks = settings["hooks"][hook_type]
            filtered_hooks = []

            for hook_config in original_hooks:
                if isinstance(hook_config, dict) and "hooks" in hook_config:
                    # Filter out ward hooks
                    hook_config["hooks"] = [
                        h for h in hook_config["hooks"]
                        if ward_hook_dir not in h
                    ]
                    if hook_config["hooks"]:
                        filtered_hooks.append(hook_config)
                    else:
                        modified = True
                else:
                    filtered_hooks.append(hook_config)

            if len(filtered_hooks) != len(original_hooks):
                modified = True

            if filtered_hooks:
                settings["hooks"][hook_type] = filtered_hooks
            else:
                del settings["hooks"][hook_type]
                modified = True

    # Clean up empty hooks dict
    if not settings.get("hooks"):
        settings.pop("hooks", None)
        modified = True

    if modified:
        try:
            save_claude_settings(settings)
            result["settings_modified"] = True
        except Exception as e:
            result["errors"].append(f"Failed to save Claude settings: {e}")
            return result

    # Remove hook script
    hook_path = get_hooks_dir() / "validate_tool.py"
    if hook_path.exists():
        try:
            hook_path.unlink()
        except Exception as e:
            result["errors"].append(f"Failed to remove hook script: {e}")

    result["success"] = len(result["errors"]) == 0
    return result


def check_hooks_status() -> dict:
    """
    Check current status of ward hooks in Claude Code.

    Returns:
        dict with status information
    """
    status = {
        "hook_script_installed": False,
        "claude_hooks_configured": False,
        "enforce_mode": False,
        "protected_tools": [],
    }

    # Check hook script
    hook_path = get_hooks_dir() / "validate_tool.py"
    status["hook_script_installed"] = hook_path.exists()

    # Check Claude settings
    settings = get_current_claude_settings()
    hooks = settings.get("hooks", {})

    ward_hook_dir = str(get_hooks_dir())

    for hook_type in ["PreToolUse", "PostToolUse"]:
        if hook_type in hooks:
            for hook_config in hooks[hook_type]:
                if isinstance(hook_config, dict):
                    for hook_cmd in hook_config.get("hooks", []):
                        if ward_hook_dir in hook_cmd:
                            status["claude_hooks_configured"] = True
                            if "WARD_ENFORCE=1" in hook_cmd:
                                status["enforce_mode"] = True
                            matcher = hook_config.get("matcher", "")
                            if matcher and matcher not in status["protected_tools"]:
                                status["protected_tools"].append(matcher)

    return status


# Validation functions that can be used standalone

def validate_bash_command(command: str, enforce: bool = False) -> tuple[bool, Optional[str], list[str]]:
    """
    Validate a bash command for dangerous patterns.

    Args:
        command: The bash command to validate
        enforce: Whether to block (True) or just warn (False)

    Returns:
        (allow, block_reason, warnings)
    """
    warnings = []

    # Compile patterns
    patterns = [
        # Critical - always block in enforce mode
        (r'find\s+.*\s+-(exec|execdir|ok|okdir)\s', 'find -exec can execute arbitrary commands', True),
        (r'\b(sh|bash|zsh)\s+-c\s', 'shell -c executes arbitrary commands', True),
        (r'\bpython[23]?\s+-c\s', 'python -c executes arbitrary code', True),
        (r'\bnode\s+(-e|--eval)\s', 'node -e executes arbitrary code', True),
        (r'tar\s+.*--checkpoint-action', 'tar checkpoint-action can execute commands', True),
        (r'(curl|wget)[^|]*\|\s*(sh|bash|python)', 'download piped to interpreter', True),
        (r'/dev/tcp/', 'potential reverse shell', True),
        (r'\bnc\s+.*-e\s', 'netcat reverse shell', True),

        # High risk - warn always, block in enforce
        (r'eval\s+["\']?\$', 'eval with variable expansion', True),
        (r'base64\s+(-d|--decode)[^|]*\|', 'base64 decode in pipeline', True),

        # Medium risk - warn only
        (r'\$\([^)]+\)', 'command substitution detected', False),
        (r'>\s*/etc/', 'writing to /etc', False),
    ]

    for pattern, reason, is_critical in patterns:
        if re.search(pattern, command, re.IGNORECASE):
            if is_critical and enforce:
                return (False, reason, warnings)
            else:
                warnings.append(reason)

    return (True, None, warnings)


def validate_tool_result_for_injection(result: str) -> tuple[bool, list[str]]:
    """
    Check if a tool result contains potential injection attempts.

    Args:
        result: The tool result string to check

    Returns:
        (safe, alerts)
    """
    alerts = []

    injection_patterns = [
        (r'</?tool_result', 'Tool result tag injection attempt'),
        (r'</?function_result', 'Function result injection attempt'),
        (r'<', 'Anthropic XML tag injection'),
        (r'</', 'Anthropic XML close tag injection'),
        (r'^Human:\s*$', 'Conversation role injection (Human)'),
        (r'^Assistant:\s*$', 'Conversation role injection (Assistant)'),
        (r'<\|endoftext\|>', 'End of text token injection'),
        (r'<\|im_start\|>', 'IM start token injection'),
        (r'<\|im_end\|>', 'IM end token injection'),
    ]

    for pattern, alert in injection_patterns:
        if re.search(pattern, result, re.IGNORECASE | re.MULTILINE):
            alerts.append(alert)

    return (len(alerts) == 0, alerts)
