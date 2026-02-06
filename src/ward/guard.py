"""Core guard logic for detecting and blocking dangerous command patterns."""

import os
import sys
from dataclasses import dataclass
from typing import Optional

from ward.config import Policy, PolicyRule
from ward.logger import log_event, EVENT_DETECT, EVENT_BLOCK, EVENT_WARN
from ward.platform_utils import (
    get_parent_process_info,
    is_ai_editor_parent,
    find_real_binary,
)


@dataclass
class GuardDecision:
    """Result of guard evaluation."""

    binary: str
    args: list[str]
    allow: bool
    matched_rule: Optional[PolicyRule] = None
    reason: Optional[str] = None
    ai_editor: Optional[str] = None


def check_dangerous_pattern(
    binary: str,
    args: list[str],
    policy: Optional[Policy] = None,
    enforce: bool = False,
) -> GuardDecision:
    """
    Check if a command matches dangerous patterns.

    Args:
        binary: The binary being executed
        args: Command line arguments (including argv[0])
        policy: Security policy to apply
        enforce: Whether to block (True) or just warn (False)

    Returns:
        GuardDecision with allow=True if safe, allow=False if blocked
    """
    if policy is None:
        policy = Policy.load()

    decision = GuardDecision(
        binary=binary,
        args=args,
        allow=True,
    )

    # Get AI editor context
    decision.ai_editor = is_ai_editor_parent()

    # Get rules for this binary
    rules = policy.get_rules_for_binary(binary)

    if not rules:
        return decision

    # Check each rule
    for rule in rules:
        if _matches_rule(args, rule):
            decision.matched_rule = rule
            decision.reason = rule.description

            # Determine action
            if rule.action == "block" and enforce:
                decision.allow = False
                _log_block(decision)
            elif rule.action == "warn" or not enforce:
                _log_warn(decision)
            else:
                _log_detect(decision)

            break  # First match wins

    return decision


def _matches_rule(args: list[str], rule: PolicyRule) -> bool:
    """Check if arguments match a policy rule."""
    args_str = " ".join(args)

    for dangerous_arg in rule.dangerous_args:
        # Direct argument match
        if dangerous_arg in args:
            return True

        # Prefix match for things like --checkpoint-action=exec
        if dangerous_arg.endswith("="):
            for arg in args:
                if arg.startswith(dangerous_arg):
                    return True

        # Contains match for patterns like --checkpoint-action=exec=
        for arg in args:
            if dangerous_arg in arg:
                return True

    return False


def _log_block(decision: GuardDecision) -> None:
    """Log a blocked command."""
    parent_info = get_parent_process_info()

    log_event(
        event_type=EVENT_BLOCK,
        binary=decision.binary,
        args=decision.args,
        blocked=True,
        reason=decision.reason,
        parent_process=parent_info,
        ai_editor=decision.ai_editor,
    )


def _log_warn(decision: GuardDecision) -> None:
    """Log a warning about a dangerous command."""
    parent_info = get_parent_process_info()

    log_event(
        event_type=EVENT_WARN,
        binary=decision.binary,
        args=decision.args,
        blocked=False,
        reason=decision.reason,
        parent_process=parent_info,
        ai_editor=decision.ai_editor,
    )


def _log_detect(decision: GuardDecision) -> None:
    """Log detection of a potentially dangerous command."""
    parent_info = get_parent_process_info()

    log_event(
        event_type=EVENT_DETECT,
        binary=decision.binary,
        args=decision.args,
        blocked=False,
        reason=decision.reason,
        parent_process=parent_info,
        ai_editor=decision.ai_editor,
    )


def guard_exec(binary: str, args: list[str], enforce: bool = False) -> int:
    """
    Guard execution of a binary.

    This is the main entry point for wrapper scripts.

    Args:
        binary: Name of the binary being wrapped
        args: Full argv (args[0] is typically the binary name)
        enforce: Whether to block dangerous patterns

    Returns:
        Exit code (0 if exec succeeded, non-zero on error or block)
    """
    # Check for dangerous patterns
    policy = Policy.load()
    decision = check_dangerous_pattern(binary, args, policy, enforce)

    if not decision.allow:
        # Print block message to stderr
        print(
            f"[ward] BLOCKED: {binary} with dangerous arguments",
            file=sys.stderr,
        )
        print(
            f"[ward] Reason: {decision.reason}",
            file=sys.stderr,
        )
        print(
            f"[ward] Args: {' '.join(args)}",
            file=sys.stderr,
        )
        print(
            f"[ward] To allow, remove --enforce or modify policy",
            file=sys.stderr,
        )
        return 1

    # Find the real binary
    real_binary = find_real_binary(binary)

    if real_binary is None:
        print(
            f"[ward] ERROR: Could not find real binary: {binary}",
            file=sys.stderr,
        )
        return 127

    # Exec the real binary
    try:
        # Replace current process with the real binary
        os.execv(str(real_binary), args)
    except OSError as e:
        print(
            f"[ward] ERROR: Failed to exec {real_binary}: {e}",
            file=sys.stderr,
        )
        return 126

    # Should never reach here
    return 0


def check_command_safety(command: str, enforce: bool = False) -> GuardDecision:
    """
    Check if a shell command string is safe.

    This is for checking commands before they're run (e.g., in shell -c).

    Args:
        command: Shell command string
        enforce: Whether blocking is enabled

    Returns:
        GuardDecision
    """
    import shlex

    # Try to parse the command
    try:
        parts = shlex.split(command)
    except ValueError:
        # Can't parse, treat as potentially dangerous
        return GuardDecision(
            binary="shell",
            args=[command],
            allow=not enforce,
            reason="Unparseable command",
        )

    if not parts:
        return GuardDecision(
            binary="shell",
            args=[],
            allow=True,
        )

    # Check the first command in the pipeline
    binary = parts[0]
    return check_dangerous_pattern(binary, parts, enforce=enforce)


# Specific pattern detectors for common attack vectors


def detect_curl_pipe_sh(args: list[str]) -> bool:
    """Detect curl | sh pattern (download and execute)."""
    args_str = " ".join(args).lower()

    dangerous_patterns = [
        "curl",
        "wget",
    ]

    pipe_patterns = [
        "| sh",
        "| bash",
        "| zsh",
        "|sh",
        "|bash",
        "|zsh",
        "| /bin/sh",
        "| /bin/bash",
    ]

    for cmd in dangerous_patterns:
        if cmd in args_str:
            for pipe in pipe_patterns:
                if pipe in args_str:
                    return True

    return False


def detect_base64_decode_exec(args: list[str]) -> bool:
    """Detect base64 decode and execute patterns."""
    args_str = " ".join(args).lower()

    patterns = [
        "base64 -d",
        "base64 --decode",
        "| sh",
        "| bash",
    ]

    # Need both base64 decode and execution
    has_decode = any(p in args_str for p in ["base64 -d", "base64 --decode"])
    has_exec = any(p in args_str for p in ["| sh", "| bash", "|sh", "|bash"])

    return has_decode and has_exec


def detect_reverse_shell(args: list[str]) -> bool:
    """Detect common reverse shell patterns."""
    args_str = " ".join(args).lower()

    patterns = [
        "/dev/tcp/",
        "nc -e",
        "ncat -e",
        "bash -i",
        "mkfifo",
        "telnet",
        "python -c.*socket",
        "perl -e.*socket",
    ]

    for pattern in patterns:
        if pattern in args_str:
            return True

    return False
