"""Protection installation and management."""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from ward.config import GuardState, Policy
from ward.logger import log_event, EVENT_PROTECT
from ward.platform_utils import (
    get_guard_dir,
    get_guarded_bin_dir,
    get_home_dir,
    ensure_guard_dirs,
)
from ward.wrappers.wrapper_template import (
    install_all_wrappers,
    get_installed_wrappers,
    WRAPPED_BINARIES,
)


# Shell profile snippet for global activation
PROFILE_SNIPPET = '''
# ward PATH modification
# Added by: ward protect --global
# To remove: ward uninstall
if [ -d "$HOME/.ward/guarded-bin" ]; then
    export PATH="$HOME/.ward/guarded-bin:$PATH"
fi
'''

PROFILE_MARKER_START = "# >>> ward >>>"
PROFILE_MARKER_END = "# <<< ward <<<"


def install_protection(
    enforce: bool = False,
    global_mode: bool = False,
    confirm_callback=None,
) -> dict:
    """
    Install ward protection.

    Args:
        enforce: Enable enforce mode (blocking)
        global_mode: Add to shell profile for global activation
        confirm_callback: Function to call for user confirmation (returns bool)

    Returns:
        dict with installation results
    """
    result = {
        "success": False,
        "wrappers_installed": [],
        "profile_modified": None,
        "errors": [],
    }

    # Ensure directories exist
    ensure_guard_dirs()

    # Install default policy if not exists
    policy_file = get_guard_dir() / "policy.yaml"
    if not policy_file.exists():
        policy = Policy.default()
        policy.save(policy_file)

    # Install library for Python wrappers
    _install_library()

    # Install wrappers
    print("Installing wrapper scripts...")
    installed = install_all_wrappers(use_python=False)  # Use shell wrappers for simplicity
    result["wrappers_installed"] = installed

    if not installed:
        result["errors"].append("No wrappers were installed")
        return result

    print(f"  Installed wrappers for: {', '.join(installed)}")

    # Handle global mode
    if global_mode:
        if confirm_callback:
            print("\nGlobal mode will modify your shell profile to add guarded-bin to PATH.")
            print("This affects ALL shell sessions, not just ward launched processes.")
            if not confirm_callback("Proceed with global mode?"):
                print("Skipping global mode installation.")
            else:
                profile_path = _install_profile_snippet()
                if profile_path:
                    result["profile_modified"] = str(profile_path)
                    print(f"  Modified: {profile_path}")
                else:
                    result["errors"].append("Failed to modify shell profile")

    # Update state
    state = GuardState(
        protected=True,
        enforce_mode=enforce,
        wrappers_installed=installed,
        profile_modified=result.get("profile_modified"),
        activated_at=datetime.utcnow().isoformat() + "Z",
    )
    state.save()

    # Log the event
    log_event(
        event_type=EVENT_PROTECT,
        extra={
            "action": "install",
            "wrappers": installed,
            "enforce": enforce,
            "global_mode": global_mode,
        },
    )

    result["success"] = True

    # Print next steps
    print("\nProtection installed successfully!")
    print("\nNext steps:")
    if global_mode and result.get("profile_modified"):
        print("  1. Restart your shell or run: source ~/.zshrc (or ~/.bashrc)")
        print("  2. All commands will now be monitored")
    else:
        print("  1. Use 'ward launch claude' to run Claude Code with protection")
        print("  2. Use 'ward launch cursor' to run Cursor with protection")

    if not enforce:
        print("\n  Note: Running in OBSERVE-ONLY mode (logging but not blocking)")
        print("  Use --enforce flag to enable blocking of dangerous commands")

    return result


def _install_library() -> None:
    """
    Install ward library to a location wrappers can find.

    This copies the ward package to ~/.ward/lib/
    so that Python wrappers can import it without system-wide installation.
    """
    import shutil

    lib_dir = get_guard_dir() / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    # Find the ward package
    import ward
    pkg_dir = Path(ward.__file__).parent

    # Copy to lib directory
    dest_dir = lib_dir / "ward"
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    shutil.copytree(pkg_dir, dest_dir)


def _install_profile_snippet() -> Optional[Path]:
    """
    Install PATH modification snippet to shell profile.

    Returns:
        Path to modified profile, or None on failure
    """
    home = get_home_dir()

    # Try common shell profiles in order of preference
    profiles = [
        home / ".zshrc",
        home / ".bashrc",
        home / ".profile",
    ]

    target_profile = None
    for profile in profiles:
        if profile.exists():
            target_profile = profile
            break

    if target_profile is None:
        # Create .zshrc if nothing exists
        target_profile = home / ".zshrc"

    try:
        # Read existing content
        existing = ""
        if target_profile.exists():
            existing = target_profile.read_text()

        # Check if already installed
        if PROFILE_MARKER_START in existing:
            return target_profile

        # Append snippet
        snippet = f"\n{PROFILE_MARKER_START}\n{PROFILE_SNIPPET}\n{PROFILE_MARKER_END}\n"

        with open(target_profile, "a") as f:
            f.write(snippet)

        return target_profile

    except Exception as e:
        print(f"Failed to modify profile: {e}")
        return None


def remove_profile_snippet() -> Optional[Path]:
    """
    Remove PATH modification snippet from shell profile.

    Returns:
        Path to modified profile, or None if not found
    """
    home = get_home_dir()

    profiles = [
        home / ".zshrc",
        home / ".bashrc",
        home / ".profile",
    ]

    for profile in profiles:
        if not profile.exists():
            continue

        try:
            content = profile.read_text()

            if PROFILE_MARKER_START not in content:
                continue

            # Remove the snippet
            lines = content.split("\n")
            new_lines = []
            in_snippet = False

            for line in lines:
                if PROFILE_MARKER_START in line:
                    in_snippet = True
                    continue
                if PROFILE_MARKER_END in line:
                    in_snippet = False
                    continue
                if not in_snippet:
                    new_lines.append(line)

            # Write back
            with open(profile, "w") as f:
                f.write("\n".join(new_lines))

            return profile

        except Exception:
            continue

    return None


def get_launch_env(enforce: bool = False) -> dict:
    """
    Get environment variables for launching protected processes.

    Args:
        enforce: Enable enforce mode

    Returns:
        dict of environment variables to set
    """
    guarded_bin = get_guarded_bin_dir()

    # Build new PATH with guarded-bin first
    current_path = os.environ.get("PATH", "")
    new_path = f"{guarded_bin}:{current_path}"

    env = os.environ.copy()
    env["PATH"] = new_path
    env["AICODE_GUARD_ACTIVE"] = "1"

    if enforce:
        env["AICODE_GUARD_ENFORCE"] = "1"
    else:
        env["AICODE_GUARD_ENFORCE"] = "0"

    return env


def check_protection_status() -> dict:
    """
    Check current protection status.

    Returns:
        dict with status information
    """
    state = GuardState.load()
    guarded_bin = get_guarded_bin_dir()

    status = {
        "protected": state.protected,
        "enforce_mode": state.enforce_mode,
        "activated_at": state.activated_at,
        "wrappers_installed": get_installed_wrappers(),
        "profile_modified": state.profile_modified,
        "guarded_bin_in_path": str(guarded_bin) in os.environ.get("PATH", ""),
    }

    return status
