"""Launch AI code editors with protection enabled."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from ward.logger import log_event, EVENT_LAUNCH
from ward.platform_utils import (
    get_platform,
    get_guarded_bin_dir,
    get_home_dir,
    which,
)
from ward.protect import get_launch_env
from ward.wrappers.wrapper_template import get_installed_wrappers


def launch_claude(
    enforce: bool = False,
    extra_args: Optional[list[str]] = None,
    verbose: bool = False,
) -> int:
    """
    Launch Claude Code with protection enabled.

    Args:
        enforce: Enable enforce mode (blocking)
        extra_args: Additional arguments to pass to claude
        verbose: Print verbose output

    Returns:
        Exit code from claude process
    """
    # Check if wrappers are installed
    installed = get_installed_wrappers()
    if not installed:
        print("[ward] Warning: No wrappers installed. Run 'ward protect' first.")
        print("[ward] Launching claude without full protection.")

    # Find claude binary
    claude_path = which("claude")
    if claude_path is None:
        print("[ward] ERROR: Claude Code not found in PATH")
        print("[ward] Install Claude Code first: https://docs.anthropic.com/claude-code")
        return 127

    # Build command
    cmd = [str(claude_path)]
    if extra_args:
        cmd.extend(extra_args)

    # Get protected environment
    env = get_launch_env(enforce)

    if verbose:
        print(f"[ward] Launching: {' '.join(cmd)}")
        print(f"[ward] Mode: {'ENFORCE' if enforce else 'OBSERVE-ONLY'}")
        print(f"[ward] Protected binaries: {', '.join(installed)}")

    # Log the launch
    log_event(
        event_type=EVENT_LAUNCH,
        extra={
            "tool": "claude_code",
            "path": str(claude_path),
            "enforce": enforce,
            "args": extra_args or [],
        },
    )

    # Launch claude
    try:
        # Use exec to replace current process
        os.execve(str(claude_path), cmd, env)
    except OSError as e:
        print(f"[ward] ERROR: Failed to launch claude: {e}")
        return 126

    return 0


def launch_cursor(
    enforce: bool = False,
    extra_args: Optional[list[str]] = None,
    verbose: bool = False,
) -> int:
    """
    Launch Cursor with protection enabled.

    Note: Cursor is a desktop app, so protection is limited.
    We can set environment variables but the app may spawn
    child processes that don't inherit our PATH.

    Args:
        enforce: Enable enforce mode (blocking)
        extra_args: Additional arguments to pass to cursor
        verbose: Print verbose output

    Returns:
        Exit code (0 if launched, non-zero on error)
    """
    plat = get_platform()

    # Check if wrappers are installed
    installed = get_installed_wrappers()
    if not installed:
        print("[ward] Warning: No wrappers installed. Run 'ward protect' first.")

    # Find Cursor
    cursor_path = None

    if plat == "macos":
        candidates = [
            Path("/Applications/Cursor.app"),
            get_home_dir() / "Applications" / "Cursor.app",
        ]
        for candidate in candidates:
            if candidate.exists():
                cursor_path = candidate
                break
    elif plat == "linux":
        # Try to find cursor binary
        cursor_bin = which("cursor")
        if cursor_bin:
            cursor_path = cursor_bin
        else:
            candidates = [
                Path("/usr/bin/cursor"),
                Path("/opt/cursor/cursor"),
                get_home_dir() / ".local" / "bin" / "cursor",
            ]
            for candidate in candidates:
                if candidate.exists():
                    cursor_path = candidate
                    break

    if cursor_path is None:
        print("[ward] ERROR: Cursor not found")
        print("[ward] Install Cursor first: https://cursor.com")
        return 127

    # Get protected environment
    env = get_launch_env(enforce)

    if verbose:
        print(f"[ward] Launching: {cursor_path}")
        print(f"[ward] Mode: {'ENFORCE' if enforce else 'OBSERVE-ONLY'}")
        print(f"[ward] Protected binaries: {', '.join(installed)}")

    print("[ward] Note: Cursor is a desktop app. Protection is best-effort.")
    print("[ward] Terminal commands spawned by Cursor extensions should be protected.")

    # Log the launch
    log_event(
        event_type=EVENT_LAUNCH,
        extra={
            "tool": "cursor",
            "path": str(cursor_path),
            "enforce": enforce,
            "args": extra_args or [],
        },
    )

    # Launch Cursor
    try:
        if plat == "macos":
            # Use 'open' command on macOS
            cmd = ["open", "-a", str(cursor_path)]
            if extra_args:
                cmd.extend(["--args"] + extra_args)

            # Set environment via launchctl (best effort)
            subprocess.run(cmd, env=env)
        else:
            # Direct execution on Linux
            cmd = [str(cursor_path)]
            if extra_args:
                cmd.extend(extra_args)

            # Fork to background
            subprocess.Popen(cmd, env=env, start_new_session=True)

        return 0
    except Exception as e:
        print(f"[ward] ERROR: Failed to launch Cursor: {e}")
        return 126


def launch_shell(
    shell: str = "bash",
    enforce: bool = False,
    verbose: bool = False,
) -> int:
    """
    Launch a shell with protection enabled.

    Useful for testing and manual verification.

    Args:
        shell: Shell to launch (bash, zsh, sh)
        enforce: Enable enforce mode
        verbose: Print verbose output

    Returns:
        Exit code from shell
    """
    # Find the shell
    shell_path = which(shell)
    if shell_path is None:
        print(f"[ward] ERROR: {shell} not found in PATH")
        return 127

    # Get protected environment
    env = get_launch_env(enforce)

    installed = get_installed_wrappers()

    if verbose:
        print(f"[ward] Launching protected {shell}")
        print(f"[ward] Mode: {'ENFORCE' if enforce else 'OBSERVE-ONLY'}")
        print(f"[ward] Protected binaries: {', '.join(installed)}")

    print(f"[ward] Starting protected {shell} session...")
    print(f"[ward] Type 'exit' to return to normal shell")
    print()

    # Log the launch
    log_event(
        event_type=EVENT_LAUNCH,
        extra={
            "tool": f"shell:{shell}",
            "path": str(shell_path),
            "enforce": enforce,
        },
    )

    # Launch shell
    try:
        result = subprocess.run([str(shell_path)], env=env)
        return result.returncode
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"[ward] ERROR: Failed to launch shell: {e}")
        return 126


def run_command(
    command: list[str],
    enforce: bool = False,
    verbose: bool = False,
) -> int:
    """
    Run an arbitrary command with protection enabled.

    Args:
        command: Command and arguments to run
        enforce: Enable enforce mode
        verbose: Print verbose output

    Returns:
        Exit code from command
    """
    if not command:
        print("[ward] ERROR: No command specified")
        return 1

    # Get protected environment
    env = get_launch_env(enforce)

    installed = get_installed_wrappers()

    if verbose:
        print(f"[ward] Running: {' '.join(command)}")
        print(f"[ward] Mode: {'ENFORCE' if enforce else 'OBSERVE-ONLY'}")
        print(f"[ward] Protected binaries: {', '.join(installed)}")

    # Log the launch
    log_event(
        event_type=EVENT_LAUNCH,
        extra={
            "tool": "command",
            "command": command,
            "enforce": enforce,
        },
    )

    # Run command
    try:
        result = subprocess.run(command, env=env)
        return result.returncode
    except FileNotFoundError:
        print(f"[ward] ERROR: Command not found: {command[0]}")
        return 127
    except Exception as e:
        print(f"[ward] ERROR: Failed to run command: {e}")
        return 126
