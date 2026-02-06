"""Tests for discovery functionality."""

import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ward.discovery import (
    discover_claude_code,
    discover_cursor,
    check_guard_status,
    run_scan,
    assess_risks,
    ClaudeCodeInfo,
    CursorInfo,
    GuardStatus,
)


class TestDiscoverClaudeCode:
    """Test Claude Code discovery."""

    @patch('ward.discovery.which')
    def test_not_installed_when_not_found(self, mock_which):
        """Should report not installed when claude not in PATH."""
        mock_which.return_value = None
        info = discover_claude_code()
        assert not info.installed

    @patch('ward.discovery.which')
    def test_installed_when_found(self, mock_which):
        """Should report installed when claude found."""
        mock_which.return_value = Path("/usr/local/bin/claude")
        info = discover_claude_code()
        assert info.installed
        assert info.path == "/usr/local/bin/claude"


class TestDiscoverCursor:
    """Test Cursor discovery."""

    @patch('ward.discovery.get_platform')
    def test_macos_discovery(self, mock_platform):
        """Should check macOS-specific paths."""
        mock_platform.return_value = "macos"
        info = discover_cursor()
        # Result depends on actual system state
        assert isinstance(info.installed, bool)

    @patch('ward.discovery.get_platform')
    def test_linux_discovery(self, mock_platform):
        """Should check Linux-specific paths."""
        mock_platform.return_value = "linux"
        info = discover_cursor()
        assert isinstance(info.installed, bool)


class TestCheckGuardStatus:
    """Test guard status checking."""

    def test_returns_status_object(self):
        """Should return a GuardStatus object."""
        status = check_guard_status()
        assert isinstance(status, GuardStatus)
        assert isinstance(status.wrappers_installed, bool)
        assert isinstance(status.wrappers_in_path, bool)
        assert isinstance(status.enforce_mode, bool)


class TestAssessRisks:
    """Test risk assessment."""

    def test_auto_approve_flagged(self):
        """Should flag auto-approve as a risk."""
        claude = ClaudeCodeInfo(
            installed=True,
            auto_approve_enabled=True,
            permissions=["Bash", "Write"],
        )
        cursor = CursorInfo()
        guard = GuardStatus()

        risks = assess_risks(claude, cursor, guard)
        risk_categories = [r["category"] for r in risks]
        assert "auto_approve" in risk_categories

    def test_mcp_enabled_flagged(self):
        """Should flag MCP servers as a risk."""
        claude = ClaudeCodeInfo()
        cursor = CursorInfo(
            installed=True,
            mcp_enabled=True,
            mcp_servers=["filesystem", "github"],
        )
        guard = GuardStatus()

        risks = assess_risks(claude, cursor, guard)
        risk_categories = [r["category"] for r in risks]
        assert "mcp_enabled" in risk_categories

    def test_not_installed_flagged(self):
        """Should flag when ward not installed."""
        claude = ClaudeCodeInfo()
        cursor = CursorInfo()
        guard = GuardStatus(wrappers_installed=False)

        risks = assess_risks(claude, cursor, guard)
        risk_categories = [r["category"] for r in risks]
        assert "not_installed" in risk_categories


class TestRunScan:
    """Test full scan execution."""

    def test_returns_report(self):
        """Should return an InventoryReport."""
        report = run_scan()
        assert report.timestamp
        assert report.platform
        assert report.hostname
        assert report.user

    def test_report_has_claude_code_info(self):
        """Report should include Claude Code information."""
        report = run_scan()
        assert hasattr(report, "claude_code")
        assert isinstance(report.claude_code.installed, bool)

    def test_report_has_cursor_info(self):
        """Report should include Cursor information."""
        report = run_scan()
        assert hasattr(report, "cursor")
        assert isinstance(report.cursor.installed, bool)

    def test_report_has_guard_status(self):
        """Report should include guard status."""
        report = run_scan()
        assert hasattr(report, "guard_status")

    def test_report_has_risks(self):
        """Report should include risk assessment."""
        report = run_scan()
        assert hasattr(report, "risks")
        assert isinstance(report.risks, list)

    def test_report_to_dict(self):
        """Report should serialize to dict."""
        report = run_scan()
        data = report.to_dict()
        assert "timestamp" in data
        assert "platform" in data
        assert "claude_code" in data
        assert "cursor" in data

    def test_report_serializes_to_json(self):
        """Report dict should be JSON serializable."""
        report = run_scan()
        data = report.to_dict()
        json_str = json.dumps(data)
        assert json_str
        loaded = json.loads(json_str)
        assert loaded["platform"] == data["platform"]
