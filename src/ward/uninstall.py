"""Uninstall and cleanup for ward."""

import shutil
from pathlib import Path
from typing import Optional

from ward.config import GuardState
from ward.logger import log_event, EVENT_UNINSTALL
from ward.platform_utils import get_guard_dir, get_guarded_bin_dir
from ward.protect import remove_profile_snippet
from ward.wrappers.wrapper_template import remove_all_wrappers


def uninstall(
    keep_logs: bool = True,
    keep_reports: bool = True,
    confirm_callback=None,
) -> dict:
    """
    Uninstall ward protection.

    This removes:
    - All wrapper scripts
    - Shell profile modifications
    - State files
    - Optionally logs and reports

    Args:
        keep_logs: Keep log files
        keep_reports: Keep report files
        confirm_callback: Function to call for user confirmation

    Returns:
        dict with uninstall results
    """
    result = {
        "success": False,
        "wrappers_removed": [],
        "profile_restored": False,
        "state_cleared": False,
        "logs_removed": False,
        "reports_removed": False,
        "errors": [],
    }

    guard_dir = get_guard_dir()

    if not guard_dir.exists():
        print("[ward] Nothing to uninstall - no installation found")
        result["success"] = True
        return result

    # Log the uninstall event before we remove things
    try:
        log_event(
            event_type=EVENT_UNINSTALL,
            extra={
                "keep_logs": keep_logs,
                "keep_reports": keep_reports,
            },
        )
    except Exception:
        pass

    # Remove wrappers
    print("Removing wrapper scripts...")
    removed = remove_all_wrappers()
    result["wrappers_removed"] = removed
    if removed:
        print(f"  Removed: {', '.join(removed)}")
    else:
        print("  No wrappers found")

    # Remove guarded-bin directory if empty
    guarded_bin = get_guarded_bin_dir()
    if guarded_bin.exists():
        try:
            remaining = list(guarded_bin.iterdir())
            if not remaining:
                guarded_bin.rmdir()
        except Exception:
            pass

    # Restore shell profile
    print("Restoring shell profile...")
    profile = remove_profile_snippet()
    if profile:
        result["profile_restored"] = True
        print(f"  Restored: {profile}")
    else:
        print("  No profile modifications found")

    # Clear state
    print("Clearing state...")
    state_file = guard_dir / "state.json"
    if state_file.exists():
        try:
            state_file.unlink()
            result["state_cleared"] = True
            print("  State cleared")
        except Exception as e:
            result["errors"].append(f"Failed to remove state file: {e}")

    # Remove library copy
    lib_dir = guard_dir / "lib"
    if lib_dir.exists():
        try:
            shutil.rmtree(lib_dir)
            print("  Removed library files")
        except Exception as e:
            result["errors"].append(f"Failed to remove lib directory: {e}")

    # Handle logs
    if not keep_logs:
        logs_dir = guard_dir / "logs"
        if logs_dir.exists():
            if confirm_callback and not confirm_callback("Remove all log files?"):
                print("  Keeping logs")
            else:
                try:
                    shutil.rmtree(logs_dir)
                    result["logs_removed"] = True
                    print("  Removed logs")
                except Exception as e:
                    result["errors"].append(f"Failed to remove logs: {e}")
    else:
        print("  Keeping logs (use --remove-logs to delete)")

    # Handle reports
    if not keep_reports:
        reports_dir = guard_dir / "reports"
        if reports_dir.exists():
            if confirm_callback and not confirm_callback("Remove all report files?"):
                print("  Keeping reports")
            else:
                try:
                    shutil.rmtree(reports_dir)
                    result["reports_removed"] = True
                    print("  Removed reports")
                except Exception as e:
                    result["errors"].append(f"Failed to remove reports: {e}")
    else:
        print("  Keeping reports (use --remove-reports to delete)")

    # Remove policy file
    policy_file = guard_dir / "policy.yaml"
    if policy_file.exists():
        try:
            policy_file.unlink()
            print("  Removed policy file")
        except Exception:
            pass

    # Try to remove guard directory if empty
    try:
        remaining = list(guard_dir.iterdir())
        if not remaining:
            guard_dir.rmdir()
            print("  Removed ~/.ward directory")
    except Exception:
        pass

    result["success"] = len(result["errors"]) == 0

    if result["success"]:
        print("\nUninstall complete!")
        print("All ward protection has been removed.")
    else:
        print("\nUninstall completed with errors:")
        for error in result["errors"]:
            print(f"  - {error}")

    return result


def clean_logs(days_to_keep: int = 30) -> int:
    """
    Clean old log files.

    Args:
        days_to_keep: Keep logs from the last N days

    Returns:
        Number of files removed
    """
    import time

    logs_dir = get_guard_dir() / "logs"
    if not logs_dir.exists():
        return 0

    cutoff = time.time() - (days_to_keep * 24 * 60 * 60)
    removed = 0

    for log_file in logs_dir.iterdir():
        if log_file.is_file():
            try:
                if log_file.stat().st_mtime < cutoff:
                    log_file.unlink()
                    removed += 1
            except Exception:
                pass

    return removed


def clean_reports(days_to_keep: int = 90) -> int:
    """
    Clean old report files.

    Args:
        days_to_keep: Keep reports from the last N days

    Returns:
        Number of files removed
    """
    import time

    reports_dir = get_guard_dir() / "reports"
    if not reports_dir.exists():
        return 0

    cutoff = time.time() - (days_to_keep * 24 * 60 * 60)
    removed = 0

    for report_file in reports_dir.iterdir():
        if report_file.is_file():
            try:
                if report_file.stat().st_mtime < cutoff:
                    report_file.unlink()
                    removed += 1
            except Exception:
                pass

    return removed
