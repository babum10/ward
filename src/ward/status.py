"""Status reporting for ward."""

import json
import os
from datetime import datetime

from ward.config import GuardState, Policy
from ward.discovery import (
    discover_claude_code,
    discover_cursor,
    check_guard_status,
)
from ward.logger import get_logger
from ward.platform_utils import (
    get_platform,
    get_guard_dir,
    get_guarded_bin_dir,
    is_supported_platform,
)
from ward.wrappers.wrapper_template import get_installed_wrappers


def get_full_status() -> dict:
    """Get complete status information."""
    # Basic info
    status = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "platform": get_platform(),
        "supported": is_supported_platform(),
        "guard_dir": str(get_guard_dir()),
    }

    # Installation state
    state = GuardState.load()
    status["state"] = {
        "protected": state.protected,
        "enforce_mode": state.enforce_mode,
        "activated_at": state.activated_at,
        "profile_modified": state.profile_modified,
    }

    # Wrapper status
    wrappers = get_installed_wrappers()
    guarded_bin = get_guarded_bin_dir()
    status["wrappers"] = {
        "installed": wrappers,
        "count": len(wrappers),
        "directory": str(guarded_bin),
        "in_path": str(guarded_bin) in os.environ.get("PATH", ""),
    }

    # AI editor installations
    claude = discover_claude_code()
    cursor = discover_cursor()

    status["claude_code"] = {
        "installed": claude.installed,
        "path": claude.path,
        "version": claude.version,
        "config_dir": claude.config_dir,
        "auto_approve_enabled": claude.auto_approve_enabled,
    }

    status["cursor"] = {
        "installed": cursor.installed,
        "app_path": cursor.app_path,
        "config_dir": cursor.config_dir,
        "mcp_enabled": cursor.mcp_enabled,
        "mcp_servers": cursor.mcp_servers,
    }

    # Policy info
    policy = Policy.load()
    status["policy"] = {
        "version": policy.version,
        "rule_count": len(policy.rules),
        "binaries_covered": list(set(r.binary for r in policy.rules)),
    }

    # Recent events summary
    logger = get_logger()
    stats = logger.get_stats()
    status["events"] = {
        "total": stats.get("total_events", 0),
        "blocked": stats.get("blocked_count", 0),
        "by_binary": stats.get("by_binary", {}),
    }

    # Hooks status
    try:
        from ward.hooks import check_hooks_status
        status["hooks"] = check_hooks_status()
    except Exception:
        status["hooks"] = {
            "hook_script_installed": False,
            "claude_hooks_configured": False,
            "enforce_mode": False,
            "protected_tools": [],
        }

    return status


def format_status_text(status: dict) -> str:
    """Format status as human-readable text."""
    lines = []

    lines.append("=" * 60)
    lines.append("ward Status")
    lines.append("=" * 60)
    lines.append(f"Timestamp:  {status['timestamp']}")
    lines.append(f"Platform:   {status['platform']}")
    lines.append(f"Supported:  {'Yes' if status['supported'] else 'No'}")
    lines.append("")

    # Protection state
    lines.append("-" * 40)
    lines.append("Protection Status")
    lines.append("-" * 40)
    state = status.get("state", {})
    protected = state.get("protected", False)
    enforce = state.get("enforce_mode", False)

    if protected:
        mode = "ENFORCE" if enforce else "OBSERVE-ONLY"
        lines.append(f"  Status:       ACTIVE ({mode})")
        lines.append(f"  Activated:    {state.get('activated_at', 'unknown')}")
    else:
        lines.append("  Status:       NOT ACTIVE")

    if state.get("profile_modified"):
        lines.append(f"  Profile:      {state['profile_modified']} (modified)")
    lines.append("")

    # Wrappers
    lines.append("-" * 40)
    lines.append("Wrapper Scripts")
    lines.append("-" * 40)
    wrappers = status.get("wrappers", {})
    lines.append(f"  Installed:    {wrappers.get('count', 0)} wrappers")
    if wrappers.get("installed"):
        lines.append(f"  Binaries:     {', '.join(wrappers['installed'])}")
    lines.append(f"  Directory:    {wrappers.get('directory', 'unknown')}")
    lines.append(f"  In PATH:      {'Yes' if wrappers.get('in_path') else 'No'}")
    lines.append("")

    # AI Editors
    lines.append("-" * 40)
    lines.append("AI Code Editors")
    lines.append("-" * 40)

    claude = status.get("claude_code", {})
    if claude.get("installed"):
        lines.append("  Claude Code:")
        lines.append(f"    Path:       {claude.get('path', 'unknown')}")
        lines.append(f"    Version:    {claude.get('version', 'unknown')}")
        if claude.get("auto_approve_enabled"):
            lines.append("    Auto-approve: ENABLED (review recommended)")
    else:
        lines.append("  Claude Code:  Not installed")

    cursor = status.get("cursor", {})
    if cursor.get("installed"):
        lines.append("  Cursor:")
        lines.append(f"    App:        {cursor.get('app_path', 'unknown')}")
        if cursor.get("mcp_enabled"):
            lines.append(f"    MCP:        Enabled ({len(cursor.get('mcp_servers', []))} servers)")
    else:
        lines.append("  Cursor:       Not installed")
    lines.append("")

    # Policy
    lines.append("-" * 40)
    lines.append("Security Policy")
    lines.append("-" * 40)
    policy = status.get("policy", {})
    lines.append(f"  Version:      {policy.get('version', 'unknown')}")
    lines.append(f"  Rules:        {policy.get('rule_count', 0)}")
    lines.append(f"  Binaries:     {', '.join(policy.get('binaries_covered', []))}")
    lines.append("")

    # Claude Code Hooks
    lines.append("-" * 40)
    lines.append("Claude Code Hooks")
    lines.append("-" * 40)
    hooks = status.get("hooks", {})
    if hooks.get("claude_hooks_configured"):
        mode = "ENFORCE (blocking)" if hooks.get("enforce_mode") else "OBSERVE (warnings)"
        lines.append(f"  Status:       ACTIVE ({mode})")
        if hooks.get("protected_tools"):
            lines.append(f"  Tools:        {', '.join(hooks['protected_tools'])}")
    else:
        lines.append("  Status:       NOT CONFIGURED")
        lines.append("  Install with: ward hooks install")
    lines.append("")

    # Events
    lines.append("-" * 40)
    lines.append("Event Statistics")
    lines.append("-" * 40)
    events = status.get("events", {})
    lines.append(f"  Total:        {events.get('total', 0)}")
    lines.append(f"  Blocked:      {events.get('blocked', 0)}")
    if events.get("by_binary"):
        lines.append("  By binary:")
        for binary, count in events["by_binary"].items():
            lines.append(f"    {binary}: {count}")
    lines.append("")

    lines.append("=" * 60)

    return "\n".join(lines)


def print_status(json_output: bool = False) -> int:
    """Print current status."""
    status = get_full_status()

    if json_output:
        print(json.dumps(status, indent=2))
    else:
        print(format_status_text(status))

    return 0
