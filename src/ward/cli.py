"""Command-line interface for ward."""

import argparse
import sys
from typing import Optional

from ward import __version__
from ward.platform_utils import is_supported_platform, get_platform


def confirm_action(prompt: str) -> bool:
    """Ask user for confirmation (y/N)."""
    try:
        response = input(f"{prompt} [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def cmd_demo(args) -> int:
    """Run demo mode with mock data."""
    from ward.demo import run_demo

    return run_demo(json_output=args.json, verbose=args.verbose)


def cmd_scan(args) -> int:
    """Scan for AI code editor installations and security posture."""
    from ward.discovery import run_scan, format_report_summary

    print("Scanning for AI code editor installations...")
    report = run_scan(verbose=args.verbose)

    # Save report
    report_path = report.save()

    if args.json:
        import json
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report_summary(report))
        print(f"\nReport saved to: {report_path}")

    return 0


def cmd_protect(args) -> int:
    """Install protection (wrapper scripts)."""
    from ward.protect import install_protection

    if not is_supported_platform():
        print(f"Error: Platform '{get_platform()}' is not supported")
        print("ward supports macOS and Linux")
        return 1

    print("Installing ward protection...")
    print()

    # Confirm if making changes
    if not args.yes:
        print("This will:")
        print("  - Create wrapper scripts in ~/.ward/guarded-bin/")
        print("  - Install security policy configuration")
        if args.enforce:
            print("  - Enable ENFORCE mode (dangerous commands will be BLOCKED)")
        else:
            print("  - Enable OBSERVE-ONLY mode (logging without blocking)")
        if args.global_:
            print("  - Modify your shell profile to enable protection globally")
        print()

        if not confirm_action("Proceed with installation?"):
            print("Aborted.")
            return 1

    result = install_protection(
        enforce=args.enforce,
        global_mode=args.global_,
        confirm_callback=confirm_action if not args.yes else lambda x: True,
    )

    return 0 if result["success"] else 1


def cmd_launch(args) -> int:
    """Launch an AI code editor with protection enabled."""
    from ward.launch import launch_claude, launch_cursor, launch_shell, run_command

    target = args.target.lower()

    if target == "claude":
        return launch_claude(
            enforce=args.enforce,
            extra_args=args.args,
            verbose=args.verbose,
        )
    elif target == "cursor":
        return launch_cursor(
            enforce=args.enforce,
            extra_args=args.args,
            verbose=args.verbose,
        )
    elif target == "shell":
        shell = args.shell or "bash"
        return launch_shell(
            shell=shell,
            enforce=args.enforce,
            verbose=args.verbose,
        )
    elif target == "run":
        if not args.command:
            print("Error: --command is required for 'ward launch run'")
            return 1
        return run_command(
            command=args.command,
            enforce=args.enforce,
            verbose=args.verbose,
        )
    else:
        print(f"Unknown launch target: {target}")
        print("Valid targets: claude, cursor, shell, run")
        return 1


def cmd_status(args) -> int:
    """Show current protection status."""
    from ward.status import print_status

    return print_status(json_output=args.json)


def cmd_uninstall(args) -> int:
    """Uninstall ward protection."""
    from ward.uninstall import uninstall

    print("Uninstalling ward protection...")
    print()

    if not args.yes:
        print("This will:")
        print("  - Remove all wrapper scripts")
        print("  - Restore shell profile (if modified)")
        print("  - Clear state files")
        if args.remove_logs:
            print("  - DELETE all log files")
        if args.remove_reports:
            print("  - DELETE all report files")
        print()

        if not confirm_action("Proceed with uninstall?"):
            print("Aborted.")
            return 1

    result = uninstall(
        keep_logs=not args.remove_logs,
        keep_reports=not args.remove_reports,
        confirm_callback=confirm_action if not args.yes else None,
    )

    return 0 if result["success"] else 1


def cmd_policy(args) -> int:
    """Manage security policy."""
    from ward.config import Policy
    from ward.platform_utils import get_policy_file
    import json

    if args.policy_cmd == "show":
        policy = Policy.load()
        if args.json:
            print(json.dumps(policy.to_dict(), indent=2))
        else:
            print("Security Policy")
            print("=" * 40)
            print(f"Version: {policy.version}")
            print(f"Rules: {len(policy.rules)}")
            print()
            for rule in policy.rules:
                print(f"  Binary: {rule.binary}")
                print(f"    Dangerous args: {', '.join(rule.dangerous_args)}")
                print(f"    Severity: {rule.severity}")
                print(f"    Action: {rule.action}")
                print(f"    Description: {rule.description}")
                print()
        return 0

    elif args.policy_cmd == "reset":
        if not args.yes:
            if not confirm_action("Reset policy to defaults?"):
                print("Aborted.")
                return 1

        policy = Policy.default()
        policy.save()
        print(f"Policy reset to defaults: {get_policy_file()}")
        return 0

    elif args.policy_cmd == "path":
        print(get_policy_file())
        return 0

    else:
        print("Unknown policy command. Use: show, reset, path")
        return 1


def cmd_hooks(args) -> int:
    """Manage Claude Code hooks for tool call validation."""
    from ward.hooks import (
        install_claude_hooks,
        remove_claude_hooks,
        check_hooks_status,
        get_claude_settings_path,
    )
    import json

    if args.hooks_cmd == "install":
        print("Installing Claude Code hooks...")

        if not args.yes:
            print()
            print("This will modify Claude Code settings to:")
            print("  - Validate Bash tool calls for dangerous patterns")
            print("  - Validate Write/Edit tool calls to shell scripts")
            print("  - Monitor tool results for injection attempts")
            if args.enforce:
                print("  - BLOCK dangerous tool calls (enforce mode)")
            else:
                print("  - WARN about dangerous tool calls (observe mode)")
            print()
            print(f"Settings file: {get_claude_settings_path()}")
            print()

            if not confirm_action("Proceed with hook installation?"):
                print("Aborted.")
                return 1

        result = install_claude_hooks(enforce=args.enforce)

        if result["success"]:
            print()
            print("Hooks installed successfully!")
            print(f"  Hook script: {result['hook_path']}")
            print(f"  Mode: {'ENFORCE (blocking)' if args.enforce else 'OBSERVE (warnings only)'}")
            print()
            print("Claude Code will now validate tool calls before execution.")
            print("Restart Claude Code for changes to take effect.")
            return 0
        else:
            print("Hook installation failed:")
            for error in result["errors"]:
                print(f"  - {error}")
            return 1

    elif args.hooks_cmd == "remove":
        print("Removing Claude Code hooks...")

        result = remove_claude_hooks()

        if result["success"]:
            print("Hooks removed successfully!")
            if result["settings_modified"]:
                print("Restart Claude Code for changes to take effect.")
            return 0
        else:
            print("Hook removal had errors:")
            for error in result["errors"]:
                print(f"  - {error}")
            return 1

    elif args.hooks_cmd == "status":
        status = check_hooks_status()

        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print("Claude Code Hooks Status")
            print("=" * 40)
            print(f"  Hook script installed: {'Yes' if status['hook_script_installed'] else 'No'}")
            print(f"  Claude hooks configured: {'Yes' if status['claude_hooks_configured'] else 'No'}")
            print(f"  Enforce mode: {'Yes' if status['enforce_mode'] else 'No (observe only)'}")
            if status["protected_tools"]:
                print(f"  Protected tools: {', '.join(status['protected_tools'])}")
        return 0

    else:
        print("Unknown hooks command. Use: install, remove, status")
        return 1


def cmd_logs(args) -> int:
    """View security event logs."""
    from ward.logger import get_logger
    import json

    logger = get_logger()
    events = logger.get_recent_events(args.count)

    if args.json:
        print(json.dumps(events, indent=2))
    else:
        if not events:
            print("No events logged yet.")
            return 0

        print(f"Recent Events (last {len(events)}):")
        print("=" * 80)

        for event in events:
            timestamp = event.get("timestamp", "")[:19] if event.get("timestamp") else ""
            event_type = (event.get("event_type") or "unknown").upper()
            binary = event.get("binary") or ""
            blocked = "BLOCKED" if event.get("blocked") else ""

            print(f"{timestamp}  [{event_type:8}]  {binary:10}  {blocked}")
            if args.verbose:
                event_args = event.get("args") or []
                args_str = " ".join(str(a) for a in event_args)[:60]
                print(f"             Args: {args_str}")
                if event.get("reason"):
                    print(f"             Reason: {event.get('reason')}")
                print()

    return 0


def main(argv: Optional[list] = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ward",
        description="Enterprise security tool for AI code editor deployments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ward demo                  Show demo with mock data
  ward scan                  Discover installations
  ward protect               Install protection (observe-only)
  ward protect --enforce     Install with blocking enabled
  ward launch claude         Run Claude Code with protection
  ward launch cursor         Run Cursor with protection
  ward hooks install         Install Claude Code tool validation hooks
  ward hooks install --enforce  Block dangerous tool calls
  ward status                Show protection status
  ward uninstall             Remove protection

For more information, see: https://github.com/your-org/ward
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"ward {__version__}",
    )

    # Global options
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # demo command
    demo_parser = subparsers.add_parser(
        "demo",
        help="Run demo mode with mock data",
    )
    demo_parser.set_defaults(func=cmd_demo)

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan for AI editor installations and security posture",
    )
    scan_parser.set_defaults(func=cmd_scan)

    # protect command
    protect_parser = subparsers.add_parser(
        "protect",
        help="Install protection (wrapper scripts)",
    )
    protect_parser.add_argument(
        "--enforce",
        action="store_true",
        help="Enable enforce mode (block dangerous commands)",
    )
    protect_parser.add_argument(
        "--global",
        dest="global_",
        action="store_true",
        help="Modify shell profile for global activation (requires confirmation)",
    )
    protect_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompts",
    )
    protect_parser.set_defaults(func=cmd_protect)

    # launch command
    launch_parser = subparsers.add_parser(
        "launch",
        help="Launch AI editor with protection enabled",
    )
    launch_parser.add_argument(
        "target",
        choices=["claude", "cursor", "shell", "run"],
        help="What to launch: claude, cursor, shell, or run (arbitrary command)",
    )
    launch_parser.add_argument(
        "--enforce",
        action="store_true",
        help="Enable enforce mode (block dangerous commands)",
    )
    launch_parser.add_argument(
        "--shell",
        default="bash",
        help="Shell to use (for 'launch shell')",
    )
    launch_parser.add_argument(
        "--command", "-c",
        nargs=argparse.REMAINDER,
        help="Command to run (for 'launch run')",
    )
    launch_parser.add_argument(
        "args",
        nargs="*",
        help="Additional arguments to pass to the target",
    )
    launch_parser.set_defaults(func=cmd_launch)

    # status command
    status_parser = subparsers.add_parser(
        "status",
        help="Show current protection status",
    )
    status_parser.set_defaults(func=cmd_status)

    # uninstall command
    uninstall_parser = subparsers.add_parser(
        "uninstall",
        help="Uninstall ward protection",
    )
    uninstall_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompts",
    )
    uninstall_parser.add_argument(
        "--remove-logs",
        action="store_true",
        help="Also remove log files",
    )
    uninstall_parser.add_argument(
        "--remove-reports",
        action="store_true",
        help="Also remove report files",
    )
    uninstall_parser.set_defaults(func=cmd_uninstall)

    # policy command
    policy_parser = subparsers.add_parser(
        "policy",
        help="Manage security policy",
    )
    policy_parser.add_argument(
        "policy_cmd",
        choices=["show", "reset", "path"],
        help="Policy subcommand",
    )
    policy_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompts",
    )
    policy_parser.set_defaults(func=cmd_policy)

    # logs command
    logs_parser = subparsers.add_parser(
        "logs",
        help="View security event logs",
    )
    logs_parser.add_argument(
        "-n", "--count",
        type=int,
        default=20,
        help="Number of events to show (default: 20)",
    )
    logs_parser.set_defaults(func=cmd_logs)

    # hooks command
    hooks_parser = subparsers.add_parser(
        "hooks",
        help="Manage Claude Code hooks for tool call validation",
    )
    hooks_parser.add_argument(
        "hooks_cmd",
        choices=["install", "remove", "status"],
        help="Hooks subcommand: install, remove, or status",
    )
    hooks_parser.add_argument(
        "--enforce",
        action="store_true",
        help="Enable enforce mode (block dangerous tool calls)",
    )
    hooks_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompts",
    )
    hooks_parser.set_defaults(func=cmd_hooks)

    # Parse arguments
    args = parser.parse_args(argv)

    # Handle no command
    if not hasattr(args, 'func'):
        parser.print_help()
        return 0

    # Run command
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
