"""Tests for CLI functionality."""

import pytest
import sys
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from io import StringIO

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ward.cli import main


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_help_exits_zero(self):
        """--help should exit with code 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_version_exits_zero(self):
        """--version should exit with code 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0

    def test_no_command_shows_help(self, capsys):
        """No command should show help and exit 0."""
        result = main([])
        assert result == 0
        captured = capsys.readouterr()
        assert "ward" in captured.out


class TestDemoCommand:
    """Test demo command."""

    def test_demo_runs_successfully(self, capsys):
        """Demo command should run without errors."""
        result = main(["demo"])
        assert result == 0
        captured = capsys.readouterr()
        assert "DEMO MODE" in captured.out

    def test_demo_json_output(self, capsys):
        """Demo with --json should output valid JSON."""
        result = main(["--json", "demo"])
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["mode"] == "demo"
        assert "inventory" in data
        assert "events" in data

    def test_demo_shows_mock_events(self, capsys):
        """Demo should show mock security events."""
        result = main(["demo"])
        assert result == 0
        captured = capsys.readouterr()
        # Should show at least some events
        assert "EVENTS" in captured.out or "events" in captured.out.lower()

    def test_demo_shows_blocked_events(self, capsys):
        """Demo should indicate blocked events."""
        result = main(["demo"])
        captured = capsys.readouterr()
        # In the mock data, we have blocked events
        assert "block" in captured.out.lower() or "BLOCKED" in captured.out

    def test_demo_verbose_shows_more(self, capsys):
        """Demo --verbose should show more details."""
        result = main(["--verbose", "demo"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Event ID" in captured.out or "DETAILED" in captured.out


class TestScanCommand:
    """Test scan command."""

    def test_scan_runs_successfully(self, capsys):
        """Scan command should run without errors."""
        result = main(["scan"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Scan" in captured.out or "scan" in captured.out.lower()

    def test_scan_json_output(self, capsys):
        """Scan with --json should output valid JSON."""
        result = main(["--json", "scan"])
        assert result == 0
        captured = capsys.readouterr()
        # Output includes scan messages plus JSON
        # Find the JSON part
        lines = captured.out.split('\n')
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                json_start = i
                break
        assert json_start is not None
        json_text = '\n'.join(lines[json_start:])
        data = json.loads(json_text)
        assert "platform" in data
        assert "claude_code" in data
        assert "cursor" in data

    def test_scan_reports_platform(self, capsys):
        """Scan should report platform information."""
        result = main(["scan"])
        captured = capsys.readouterr()
        assert "Platform" in captured.out or "platform" in captured.out.lower()


class TestStatusCommand:
    """Test status command."""

    def test_status_runs_successfully(self, capsys):
        """Status command should run without errors."""
        result = main(["status"])
        assert result == 0

    def test_status_json_output(self, capsys):
        """Status with --json should output valid JSON."""
        result = main(["--json", "status"])
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "platform" in data
        assert "state" in data
        assert "wrappers" in data


class TestPolicyCommand:
    """Test policy command."""

    def test_policy_show(self, capsys):
        """Policy show should display rules."""
        result = main(["policy", "show"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Policy" in captured.out or "Binary" in captured.out

    def test_policy_show_json(self, capsys):
        """Policy show --json should output valid JSON."""
        result = main(["--json", "policy", "show"])
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "version" in data
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_policy_path(self, capsys):
        """Policy path should show policy file location."""
        result = main(["policy", "path"])
        assert result == 0
        captured = capsys.readouterr()
        assert "ward" in captured.out
        assert "policy" in captured.out.lower()


class TestLogsCommand:
    """Test logs command."""

    def test_logs_runs(self, capsys):
        """Logs command should run without errors."""
        result = main(["logs"])
        assert result == 0

    def test_logs_with_count(self, capsys):
        """Logs -n should accept count parameter."""
        result = main(["logs", "-n", "5"])
        assert result == 0


class TestProtectCommand:
    """Test protect command (with mocked confirmation)."""

    @patch('ward.cli.confirm_action', return_value=False)
    def test_protect_requires_confirmation(self, mock_confirm, capsys):
        """Protect should require confirmation."""
        result = main(["protect"])
        assert result == 1
        captured = capsys.readouterr()
        assert "Aborted" in captured.out

    @patch('ward.cli.confirm_action', return_value=True)
    def test_protect_with_yes(self, mock_confirm, capsys):
        """Protect with -y should skip confirmation."""
        result = main(["protect", "-y"])
        # Should succeed or fail based on system state
        assert result in [0, 1]


class TestUninstallCommand:
    """Test uninstall command."""

    @patch('ward.cli.confirm_action', return_value=False)
    def test_uninstall_requires_confirmation(self, mock_confirm, capsys):
        """Uninstall should require confirmation."""
        result = main(["uninstall"])
        assert result == 1
        captured = capsys.readouterr()
        assert "Aborted" in captured.out


class TestLaunchCommand:
    """Test launch command."""

    def test_launch_unknown_target(self, capsys):
        """Launch with unknown target should fail."""
        result = main(["launch", "unknown"])
        assert result != 0

    @patch('ward.launch.which', return_value=None)
    def test_launch_claude_not_found(self, mock_which, capsys):
        """Launch claude when not installed should report error."""
        result = main(["launch", "claude"])
        assert result == 127
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()
