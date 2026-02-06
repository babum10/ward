"""Platform-specific utilities for macOS and Linux."""

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional


def get_platform() -> str:
    """Return 'macos', 'linux', or 'windows'."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    return "unknown"


def is_supported_platform() -> bool:
    """Check if current platform is supported."""
    return get_platform() in ("macos", "linux")


def get_home_dir() -> Path:
    """Get user home directory."""
    return Path.home()


def get_config_dir() -> Path:
    """Get platform-specific config directory."""
    plat = get_platform()
    home = get_home_dir()

    if plat == "macos":
        return home / "Library" / "Application Support"
    elif plat == "linux":
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            return Path(xdg_config)
        return home / ".config"
    else:
        return home / ".config"


def get_guard_dir() -> Path:
    """Get ward data directory."""
    return get_home_dir() / ".ward"


def get_guarded_bin_dir() -> Path:
    """Get directory for wrapper scripts."""
    return get_guard_dir() / "guarded-bin"


def get_logs_dir() -> Path:
    """Get logs directory."""
    return get_guard_dir() / "logs"


def get_reports_dir() -> Path:
    """Get reports directory."""
    return get_guard_dir() / "reports"


def get_policy_file() -> Path:
    """Get policy configuration file path."""
    return get_guard_dir() / "policy.yaml"


def ensure_guard_dirs() -> None:
    """Create all necessary ward directories."""
    dirs = [
        get_guard_dir(),
        get_guarded_bin_dir(),
        get_logs_dir(),
        get_reports_dir(),
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def which(binary: str) -> Optional[Path]:
    """Find binary in PATH, excluding guarded-bin directory."""
    guarded_bin = str(get_guarded_bin_dir())

    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for path_dir in path_dirs:
        if path_dir == guarded_bin:
            continue
        candidate = Path(path_dir) / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def find_real_binary(binary: str) -> Optional[Path]:
    """Find the real binary, skipping any guarded-bin wrappers."""
    guarded_bin = str(get_guarded_bin_dir())

    # Common system paths to search
    system_paths = []
    plat = get_platform()

    if plat == "macos":
        system_paths = [
            "/usr/bin",
            "/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
        ]
    elif plat == "linux":
        system_paths = [
            "/usr/bin",
            "/bin",
            "/usr/local/bin",
        ]

    # First check PATH, excluding guarded-bin
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for path_dir in path_dirs:
        if path_dir == guarded_bin:
            continue
        candidate = Path(path_dir) / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    # Fallback to system paths
    for path_dir in system_paths:
        candidate = Path(path_dir) / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    return None


def get_parent_process_info() -> dict:
    """Get information about parent process chain (best effort)."""
    plat = get_platform()
    info = {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "chain": [],
    }

    try:
        if plat == "linux":
            info["chain"] = _get_process_chain_linux()
        elif plat == "macos":
            info["chain"] = _get_process_chain_macos()
    except Exception:
        pass

    return info


def _get_process_chain_linux() -> list:
    """Get process chain on Linux via /proc."""
    chain = []
    pid = os.getppid()

    for _ in range(10):  # Max 10 levels
        if pid <= 1:
            break
        try:
            comm_path = Path(f"/proc/{pid}/comm")
            cmdline_path = Path(f"/proc/{pid}/cmdline")
            stat_path = Path(f"/proc/{pid}/stat")

            name = comm_path.read_text().strip() if comm_path.exists() else "unknown"
            cmdline = ""
            if cmdline_path.exists():
                cmdline = cmdline_path.read_bytes().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()

            chain.append({"pid": pid, "name": name, "cmdline": cmdline})

            # Get parent PID
            if stat_path.exists():
                stat_content = stat_path.read_text()
                # Format: pid (comm) state ppid ...
                parts = stat_content.split(')')
                if len(parts) >= 2:
                    after_comm = parts[1].split()
                    if len(after_comm) >= 2:
                        pid = int(after_comm[1])
                        continue
            break
        except Exception:
            break

    return chain


def _get_process_chain_macos() -> list:
    """Get process chain on macOS via ps."""
    chain = []
    pid = os.getppid()

    for _ in range(10):  # Max 10 levels
        if pid <= 1:
            break
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "ppid=,comm="],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode != 0:
                break

            output = result.stdout.strip()
            if not output:
                break

            parts = output.split(None, 1)
            if len(parts) >= 2:
                ppid = int(parts[0])
                name = parts[1]
                chain.append({"pid": pid, "name": name})
                pid = ppid
            else:
                break
        except Exception:
            break

    return chain


def is_ai_editor_parent() -> Optional[str]:
    """Check if a parent process is an AI editor (Claude Code or Cursor)."""
    info = get_parent_process_info()

    ai_editor_patterns = [
        ("claude", "claude_code"),
        ("cursor", "cursor"),
        ("Cursor", "cursor"),
        ("node", None),  # Could be either, needs more context
    ]

    for proc in info.get("chain", []):
        name = proc.get("name", "").lower()
        cmdline = proc.get("cmdline", "").lower()

        if "claude" in name or "claude" in cmdline:
            return "claude_code"
        if "cursor" in name or "cursor" in cmdline:
            return "cursor"

    return None


def get_shell_profile_paths() -> list[Path]:
    """Get common shell profile paths for the current user."""
    home = get_home_dir()
    profiles = []

    # Bash profiles
    profiles.extend([
        home / ".bashrc",
        home / ".bash_profile",
        home / ".profile",
    ])

    # Zsh profiles
    profiles.extend([
        home / ".zshrc",
        home / ".zprofile",
    ])

    # Fish config
    profiles.append(home / ".config" / "fish" / "config.fish")

    return [p for p in profiles if p.exists()]
