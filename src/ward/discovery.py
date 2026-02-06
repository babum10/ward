"""Discovery module for finding AI code editor installations."""

import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from ward.platform_utils import (
    get_platform,
    get_home_dir,
    get_config_dir,
    get_guarded_bin_dir,
    get_reports_dir,
    which,
)


@dataclass
class ClaudeCodeInfo:
    """Information about Claude Code installation."""

    installed: bool = False
    path: Optional[str] = None
    version: Optional[str] = None
    config_dir: Optional[str] = None
    settings: dict = field(default_factory=dict)
    auto_approve_enabled: bool = False
    permissions: list[str] = field(default_factory=list)


@dataclass
class CursorInfo:
    """Information about Cursor installation."""

    installed: bool = False
    app_path: Optional[str] = None
    config_dir: Optional[str] = None
    version: Optional[str] = None
    mcp_enabled: bool = False
    mcp_servers: list[str] = field(default_factory=list)


@dataclass
class GuardStatus:
    """Status of ward protection."""

    wrappers_installed: bool = False
    wrappers_in_path: bool = False
    enforce_mode: bool = False
    protected_binaries: list[str] = field(default_factory=list)


@dataclass
class InventoryReport:
    """Complete inventory report."""

    timestamp: str = ""
    platform: str = ""
    hostname: str = ""
    user: str = ""
    claude_code: ClaudeCodeInfo = field(default_factory=ClaudeCodeInfo)
    cursor: CursorInfo = field(default_factory=CursorInfo)
    guard_status: GuardStatus = field(default_factory=GuardStatus)
    risks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert report to dictionary."""
        return {
            "timestamp": self.timestamp,
            "platform": self.platform,
            "hostname": self.hostname,
            "user": self.user,
            "claude_code": {
                "installed": self.claude_code.installed,
                "path": self.claude_code.path,
                "version": self.claude_code.version,
                "config_dir": self.claude_code.config_dir,
                "auto_approve_enabled": self.claude_code.auto_approve_enabled,
                "permissions": self.claude_code.permissions,
            },
            "cursor": {
                "installed": self.cursor.installed,
                "app_path": self.cursor.app_path,
                "config_dir": self.cursor.config_dir,
                "version": self.cursor.version,
                "mcp_enabled": self.cursor.mcp_enabled,
                "mcp_servers": self.cursor.mcp_servers,
            },
            "guard_status": {
                "wrappers_installed": self.guard_status.wrappers_installed,
                "wrappers_in_path": self.guard_status.wrappers_in_path,
                "enforce_mode": self.guard_status.enforce_mode,
                "protected_binaries": self.guard_status.protected_binaries,
            },
            "risks": self.risks,
        }

    def save(self, path: Optional[Path] = None) -> Path:
        """Save report to JSON file."""
        if path is None:
            reports_dir = get_reports_dir()
            reports_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = reports_dir / f"{timestamp}.json"

        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

        return path


def discover_claude_code() -> ClaudeCodeInfo:
    """Discover Claude Code installation and configuration."""
    info = ClaudeCodeInfo()
    home = get_home_dir()
    plat = get_platform()

    # Try to find claude binary
    claude_path = which("claude")
    if claude_path:
        info.installed = True
        info.path = str(claude_path)

        # Try to get version
        try:
            result = subprocess.run(
                [str(claude_path), "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                info.version = result.stdout.strip()
        except Exception:
            pass

    # Look for config directory
    config_locations = []

    if plat == "macos":
        config_locations = [
            home / ".claude",
            home / "Library" / "Application Support" / "claude",
            home / "Library" / "Application Support" / "Claude",
        ]
    elif plat == "linux":
        config_locations = [
            home / ".claude",
            home / ".config" / "claude",
            home / ".config" / "Claude",
        ]

    for config_dir in config_locations:
        if config_dir.exists():
            info.config_dir = str(config_dir)

            # Check for settings file
            settings_file = config_dir / "settings.json"
            if settings_file.exists():
                try:
                    with open(settings_file) as f:
                        info.settings = json.load(f)

                    # Check for auto-approve settings
                    permissions = info.settings.get("permissions", {})
                    if permissions:
                        info.permissions = list(permissions.keys())

                    # Check if dangerous permissions are auto-approved
                    auto_approve = info.settings.get("autoApprove", [])
                    if auto_approve:
                        info.auto_approve_enabled = True
                        info.permissions.extend(auto_approve)

                except Exception:
                    pass
            break

    return info


def discover_cursor() -> CursorInfo:
    """Discover Cursor installation and configuration."""
    info = CursorInfo()
    home = get_home_dir()
    plat = get_platform()

    # Check for Cursor app
    app_locations = []
    config_locations = []

    if plat == "macos":
        app_locations = [
            Path("/Applications/Cursor.app"),
            home / "Applications" / "Cursor.app",
        ]
        config_locations = [
            home / "Library" / "Application Support" / "Cursor",
            home / ".cursor",
        ]
    elif plat == "linux":
        app_locations = [
            Path("/usr/share/cursor"),
            Path("/opt/cursor"),
            home / ".local" / "share" / "cursor",
            Path("/usr/bin/cursor"),
        ]
        config_locations = [
            home / ".config" / "Cursor",
            home / ".config" / "cursor",
            home / ".cursor",
        ]

    # Check app locations
    for app_path in app_locations:
        if app_path.exists():
            info.installed = True
            info.app_path = str(app_path)
            break

    # Check config locations
    for config_dir in config_locations:
        if config_dir.exists():
            info.config_dir = str(config_dir)

            # Look for MCP configuration
            mcp_config_paths = [
                config_dir / "mcp.json",
                config_dir / "User" / "settings.json",
            ]

            for mcp_path in mcp_config_paths:
                if mcp_path.exists():
                    try:
                        with open(mcp_path) as f:
                            config = json.load(f)

                        # Check for MCP servers
                        if "mcpServers" in config or "mcp" in config:
                            info.mcp_enabled = True
                            servers = config.get("mcpServers", config.get("mcp", {}).get("servers", {}))
                            if isinstance(servers, dict):
                                info.mcp_servers = list(servers.keys())
                            elif isinstance(servers, list):
                                info.mcp_servers = servers
                    except Exception:
                        pass
            break

    return info


def check_guard_status() -> GuardStatus:
    """Check current ward protection status."""
    status = GuardStatus()
    guarded_bin = get_guarded_bin_dir()

    # Check if wrapper directory exists and has wrappers
    if guarded_bin.exists():
        wrappers = list(guarded_bin.glob("*"))
        if wrappers:
            status.wrappers_installed = True
            status.protected_binaries = [w.name for w in wrappers if w.is_file()]

    # Check if guarded-bin is in current PATH
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    status.wrappers_in_path = str(guarded_bin) in path_dirs

    # Check enforce mode from state
    from ward.config import GuardState

    state = GuardState.load()
    status.enforce_mode = state.enforce_mode

    return status


def assess_risks(
    claude_info: ClaudeCodeInfo,
    cursor_info: CursorInfo,
    guard_status: GuardStatus,
) -> list[dict]:
    """Assess security risks based on discovered configuration."""
    risks = []

    # Claude Code risks
    if claude_info.installed:
        if claude_info.auto_approve_enabled:
            risks.append({
                "severity": "high",
                "category": "auto_approve",
                "tool": "claude_code",
                "description": "Claude Code has auto-approve enabled for some permissions",
                "details": claude_info.permissions,
                "recommendation": "Review auto-approved permissions and consider using ward protection",
            })

        if not guard_status.wrappers_in_path:
            risks.append({
                "severity": "medium",
                "category": "unprotected",
                "tool": "claude_code",
                "description": "Claude Code is not running with ward protection",
                "recommendation": "Use 'ward launch claude' to run with protection",
            })

    # Cursor risks
    if cursor_info.installed:
        if cursor_info.mcp_enabled:
            risks.append({
                "severity": "medium",
                "category": "mcp_enabled",
                "tool": "cursor",
                "description": "Cursor has MCP servers enabled",
                "details": cursor_info.mcp_servers,
                "recommendation": "Review MCP server configurations for security implications",
            })

    # General risks
    if not guard_status.wrappers_installed:
        risks.append({
            "severity": "info",
            "category": "not_installed",
            "tool": "ward",
            "description": "ward wrappers are not installed",
            "recommendation": "Run 'ward protect' to install protection",
        })
    elif guard_status.wrappers_installed and not guard_status.enforce_mode:
        risks.append({
            "severity": "info",
            "category": "observe_only",
            "tool": "ward",
            "description": "ward is in observe-only mode (not blocking)",
            "recommendation": "Use --enforce flag to enable blocking of dangerous commands",
        })

    return risks


def run_scan(verbose: bool = False) -> InventoryReport:
    """Run a full discovery scan and return inventory report."""
    import socket

    report = InventoryReport(
        timestamp=datetime.utcnow().isoformat() + "Z",
        platform=get_platform(),
        hostname=socket.gethostname(),
        user=os.environ.get("USER", "unknown"),
    )

    # Discover installations
    report.claude_code = discover_claude_code()
    report.cursor = discover_cursor()
    report.guard_status = check_guard_status()

    # Assess risks
    report.risks = assess_risks(
        report.claude_code,
        report.cursor,
        report.guard_status,
    )

    return report


def format_report_summary(report: InventoryReport) -> str:
    """Format report as human-readable summary."""
    lines = []
    lines.append("=" * 60)
    lines.append("ward Scan Report")
    lines.append("=" * 60)
    lines.append(f"Timestamp: {report.timestamp}")
    lines.append(f"Platform:  {report.platform}")
    lines.append(f"Host:      {report.hostname}")
    lines.append(f"User:      {report.user}")
    lines.append("")

    # Claude Code section
    lines.append("-" * 40)
    lines.append("Claude Code")
    lines.append("-" * 40)
    if report.claude_code.installed:
        lines.append(f"  Status:     Installed")
        lines.append(f"  Path:       {report.claude_code.path or 'unknown'}")
        lines.append(f"  Version:    {report.claude_code.version or 'unknown'}")
        lines.append(f"  Config:     {report.claude_code.config_dir or 'not found'}")
        if report.claude_code.auto_approve_enabled:
            lines.append(f"  Auto-approve: ENABLED (review recommended)")
    else:
        lines.append("  Status:     Not installed")
    lines.append("")

    # Cursor section
    lines.append("-" * 40)
    lines.append("Cursor")
    lines.append("-" * 40)
    if report.cursor.installed:
        lines.append(f"  Status:     Installed")
        lines.append(f"  App:        {report.cursor.app_path or 'unknown'}")
        lines.append(f"  Config:     {report.cursor.config_dir or 'not found'}")
        if report.cursor.mcp_enabled:
            lines.append(f"  MCP:        Enabled ({len(report.cursor.mcp_servers)} servers)")
    else:
        lines.append("  Status:     Not installed")
    lines.append("")

    # Protection status
    lines.append("-" * 40)
    lines.append("ward Protection")
    lines.append("-" * 40)
    lines.append(f"  Wrappers installed: {'Yes' if report.guard_status.wrappers_installed else 'No'}")
    lines.append(f"  Active in PATH:     {'Yes' if report.guard_status.wrappers_in_path else 'No'}")
    lines.append(f"  Enforce mode:       {'Yes' if report.guard_status.enforce_mode else 'No (observe-only)'}")
    if report.guard_status.protected_binaries:
        lines.append(f"  Protected binaries: {', '.join(report.guard_status.protected_binaries)}")
    lines.append("")

    # Risks section
    if report.risks:
        lines.append("-" * 40)
        lines.append("Security Findings")
        lines.append("-" * 40)
        for risk in report.risks:
            severity = risk.get("severity", "info").upper()
            desc = risk.get("description", "")
            rec = risk.get("recommendation", "")
            lines.append(f"  [{severity}] {desc}")
            if rec:
                lines.append(f"           -> {rec}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)
