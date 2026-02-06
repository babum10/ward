"""Logging system for ward with rotation."""

import json
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from ward.platform_utils import get_logs_dir, ensure_guard_dirs


# Event types
EVENT_SCAN = "scan"
EVENT_DETECT = "detect"
EVENT_BLOCK = "block"
EVENT_WARN = "warn"
EVENT_LAUNCH = "launch"
EVENT_PROTECT = "protect"
EVENT_UNINSTALL = "uninstall"


class SecurityEventLogger:
    """Logger for security events with structured JSON output."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or get_logs_dir()
        ensure_guard_dirs()

        self._setup_loggers()

    def _setup_loggers(self) -> None:
        """Set up file and console loggers."""
        # Main event log (JSON lines format)
        self.event_log_path = self.log_dir / "events.jsonl"

        # Human-readable log
        self.readable_log_path = self.log_dir / "ward.log"

        # Set up rotating file handler for readable logs
        self.file_handler = RotatingFileHandler(
            self.readable_log_path,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        self.file_handler.setLevel(logging.DEBUG)
        self.file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )

        # Set up logger
        self.logger = logging.getLogger("ward")
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.file_handler)

    def log_event(
        self,
        event_type: str,
        binary: Optional[str] = None,
        args: Optional[list[str]] = None,
        blocked: bool = False,
        reason: Optional[str] = None,
        parent_process: Optional[dict] = None,
        ai_editor: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> dict:
        """Log a security event."""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "binary": binary,
            "args": args,
            "blocked": blocked,
            "reason": reason,
            "parent_process": parent_process,
            "ai_editor": ai_editor,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "cwd": os.getcwd(),
            "user": os.environ.get("USER", "unknown"),
        }

        if extra:
            event.update(extra)

        # Write to JSONL file
        with open(self.event_log_path, "a") as f:
            f.write(json.dumps(event) + "\n")

        # Also write human-readable version
        msg = self._format_readable(event)
        if blocked:
            self.logger.warning(msg)
        else:
            self.logger.info(msg)

        return event

    def _format_readable(self, event: dict) -> str:
        """Format event for human-readable log."""
        event_type = event.get("event_type", "unknown")
        binary = event.get("binary", "")
        blocked = event.get("blocked", False)
        reason = event.get("reason", "")
        ai_editor = event.get("ai_editor", "")

        parts = [f"[{event_type.upper()}]"]

        if binary:
            parts.append(f"binary={binary}")

        if blocked:
            parts.append("BLOCKED")

        if reason:
            parts.append(f"reason={reason}")

        if ai_editor:
            parts.append(f"editor={ai_editor}")

        return " ".join(parts)

    def get_recent_events(self, count: int = 50) -> list[dict]:
        """Get recent events from the log."""
        events = []

        if not self.event_log_path.exists():
            return events

        try:
            with open(self.event_log_path, "r") as f:
                lines = f.readlines()

            for line in lines[-count:]:
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass

        return events

    def get_stats(self) -> dict:
        """Get statistics from the event log."""
        events = self.get_recent_events(1000)

        stats = {
            "total_events": len(events),
            "blocked_count": sum(1 for e in events if e.get("blocked")),
            "warned_count": sum(1 for e in events if e.get("event_type") == EVENT_WARN),
            "by_binary": {},
            "by_editor": {},
        }

        for event in events:
            binary = event.get("binary")
            if binary:
                stats["by_binary"][binary] = stats["by_binary"].get(binary, 0) + 1

            editor = event.get("ai_editor")
            if editor:
                stats["by_editor"][editor] = stats["by_editor"].get(editor, 0) + 1

        return stats


# Global logger instance
_logger: Optional[SecurityEventLogger] = None


def get_logger() -> SecurityEventLogger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        _logger = SecurityEventLogger()
    return _logger


def log_event(**kwargs) -> dict:
    """Convenience function to log an event."""
    return get_logger().log_event(**kwargs)
