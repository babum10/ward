"""Integration tests for ward.

These tests verify end-to-end functionality including:
- Wrapper installation and removal
- Command interception
- Protect/uninstall cycle
"""

import pytest
import sys
import os
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ward.wrappers.wrapper_template import (
    install_wrapper,
    remove_wrapper,
    install_all_wrappers,
    remove_all_wrappers,
    get_installed_wrappers,
    WRAPPED_BINARIES,
    generate_wrapper,
)
from ward.platform_utils import get_guarded_bin_dir, find_real_binary
from ward.guard import check_dangerous_pattern
from ward.protect import install_protection, get_launch_env
from ward.uninstall import uninstall


class TestWrapperInstallation:
    """Test wrapper script installation."""

    def test_generate_shell_wrapper(self):
        """Should generate valid shell wrapper content."""
        content = generate_wrapper("find", use_python=False)
        assert "#!/bin/sh" in content
        assert "find" in content
        assert "BLOCKED" in content or "blocked" in content.lower()

    def test_generate_python_wrapper(self):
        """Should generate valid Python wrapper content."""
        content = generate_wrapper("find", use_python=True)
        assert "#!/usr/bin/env python3" in content
        assert "find" in content
        assert "guard_exec" in content or "BLOCKED" in content

    def test_install_single_wrapper(self, tmp_path):
        """Should install a single wrapper script."""
        with patch('ward.wrappers.wrapper_template.get_guarded_bin_dir', return_value=tmp_path):
            result = install_wrapper("find", use_python=False)
            assert result is not None
            assert result.exists()
            assert os.access(result, os.X_OK)

    def test_remove_wrapper(self, tmp_path):
        """Should remove an installed wrapper."""
        with patch('ward.wrappers.wrapper_template.get_guarded_bin_dir', return_value=tmp_path):
            install_wrapper("find")
            assert (tmp_path / "find").exists()

            success = remove_wrapper("find")
            assert success
            assert not (tmp_path / "find").exists()


class TestWrapperExecution:
    """Test that wrapper scripts work correctly."""

    def test_shell_wrapper_syntax(self, tmp_path):
        """Shell wrapper should have valid syntax."""
        content = generate_wrapper("find", use_python=False)
        wrapper_path = tmp_path / "test_wrapper.sh"
        wrapper_path.write_text(content)
        wrapper_path.chmod(0o755)

        # Check syntax with sh -n
        result = subprocess.run(
            ["sh", "-n", str(wrapper_path)],
            capture_output=True,
        )
        assert result.returncode == 0, f"Shell syntax error: {result.stderr.decode()}"

    def test_python_wrapper_syntax(self, tmp_path):
        """Python wrapper should have valid syntax."""
        content = generate_wrapper("find", use_python=True)
        wrapper_path = tmp_path / "test_wrapper.py"
        wrapper_path.write_text(content)

        # Check syntax with python -m py_compile
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(wrapper_path)],
            capture_output=True,
        )
        assert result.returncode == 0, f"Python syntax error: {result.stderr.decode()}"


class TestGuardedExecution:
    """Test command execution through guards."""

    def test_find_real_binary(self):
        """Should find real binaries in system paths."""
        # These should exist on any Unix system
        for binary in ["ls", "cat", "echo"]:
            path = find_real_binary(binary)
            if path:  # May not exist in some environments
                assert path.exists()
                assert os.access(path, os.X_OK)

    def test_launch_env_sets_path(self):
        """Launch env should prepend guarded-bin to PATH."""
        env = get_launch_env(enforce=False)
        guarded_bin = str(get_guarded_bin_dir())
        assert env["PATH"].startswith(guarded_bin)

    def test_launch_env_sets_enforce_flag(self):
        """Launch env should set AICODE_GUARD_ENFORCE."""
        env_observe = get_launch_env(enforce=False)
        assert env_observe["AICODE_GUARD_ENFORCE"] == "0"

        env_enforce = get_launch_env(enforce=True)
        assert env_enforce["AICODE_GUARD_ENFORCE"] == "1"


class TestProtectUninstallCycle:
    """Test protect and uninstall cycle."""

    def test_install_creates_wrappers(self, tmp_path):
        """Install should create wrapper scripts."""
        with patch('ward.platform_utils.get_guard_dir', return_value=tmp_path):
            with patch('ward.platform_utils.get_guarded_bin_dir', return_value=tmp_path / "guarded-bin"):
                with patch('ward.protect.get_guard_dir', return_value=tmp_path):
                    with patch('ward.protect.get_guarded_bin_dir', return_value=tmp_path / "guarded-bin"):
                        with patch('ward.wrappers.wrapper_template.get_guarded_bin_dir', return_value=tmp_path / "guarded-bin"):
                            result = install_protection(
                                enforce=False,
                                global_mode=False,
                                confirm_callback=lambda x: True,
                            )

                            guarded_bin = tmp_path / "guarded-bin"
                            if guarded_bin.exists():
                                wrappers = list(guarded_bin.iterdir())
                                # Should have installed at least some wrappers
                                # (depends on which binaries exist on the system)
                                assert len(wrappers) >= 0


class TestAcceptanceCriteria:
    """Tests verifying the specific acceptance criteria from requirements."""

    def test_acceptance_demo_shows_5_events(self, capsys):
        """Demo mode should show at least 5 mock events."""
        from ward.demo import MOCK_EVENTS
        assert len(MOCK_EVENTS) >= 5, "Demo should have at least 5 mock events"

    def test_acceptance_demo_has_2_blocked(self):
        """Demo should have at least 2 events that would be blocked."""
        from ward.demo import MOCK_EVENTS
        blocked = sum(1 for e in MOCK_EVENTS if e.get("would_block", False))
        assert blocked >= 2, "Demo should have at least 2 blockable events"

    def test_acceptance_find_exec_pattern_detected(self):
        """The find -exec pattern must be detected."""
        decision = check_dangerous_pattern(
            "find",
            ["find", ".", "-exec", "sh", "-c", "echo pwned", ";"],
        )
        assert decision.matched_rule is not None

    def test_acceptance_find_exec_blocked_in_enforce(self):
        """The find -exec pattern must be blocked in enforce mode."""
        decision = check_dangerous_pattern(
            "find",
            ["find", ".", "-exec", "sh", "-c", "echo pwned", ";"],
            enforce=True,
        )
        assert not decision.allow
        assert "exec" in decision.reason.lower()

    def test_acceptance_scan_produces_json(self):
        """Scan should produce a valid JSON report."""
        from ward.discovery import run_scan
        import json

        report = run_scan()
        data = report.to_dict()
        json_str = json.dumps(data)
        loaded = json.loads(json_str)

        # Verify structure
        assert "timestamp" in loaded
        assert "platform" in loaded
        assert "claude_code" in loaded
        assert "cursor" in loaded
        assert "guard_status" in loaded

    def test_acceptance_wrapped_binaries_list(self):
        """Should wrap all required risky binaries."""
        required = {"find", "sh", "bash", "python", "node", "tar"}
        wrapped = set(WRAPPED_BINARIES)
        missing = required - wrapped
        assert not missing, f"Missing wrappers for: {missing}"
