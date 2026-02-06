"""Configuration management for ward."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ward.platform_utils import get_guard_dir, get_policy_file


@dataclass
class GuardConfig:
    """Runtime configuration for ward."""

    enforce: bool = False
    verbose: bool = False
    json_output: bool = False
    log_level: str = "INFO"


@dataclass
class PolicyRule:
    """A single policy rule for detecting dangerous patterns."""

    binary: str
    dangerous_args: list[str]
    description: str
    severity: str = "high"
    action: str = "block"  # block, warn, log


@dataclass
class Policy:
    """Security policy configuration."""

    version: str = "1.0"
    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def default(cls) -> "Policy":
        """Create default policy with known dangerous patterns."""
        rules = [
            # find command - arbitrary code execution via -exec
            PolicyRule(
                binary="find",
                dangerous_args=["-exec", "-execdir", "-ok", "-okdir"],
                description="find with -exec can execute arbitrary commands",
                severity="critical",
            ),
            # Shell interpreters with -c
            PolicyRule(
                binary="sh",
                dangerous_args=["-c"],
                description="sh -c executes arbitrary shell commands",
                severity="critical",
            ),
            PolicyRule(
                binary="bash",
                dangerous_args=["-c"],
                description="bash -c executes arbitrary shell commands",
                severity="critical",
            ),
            PolicyRule(
                binary="zsh",
                dangerous_args=["-c"],
                description="zsh -c executes arbitrary shell commands",
                severity="critical",
            ),
            # Python arbitrary code execution
            PolicyRule(
                binary="python",
                dangerous_args=["-c"],
                description="python -c executes arbitrary Python code",
                severity="critical",
            ),
            PolicyRule(
                binary="python3",
                dangerous_args=["-c"],
                description="python3 -c executes arbitrary Python code",
                severity="critical",
            ),
            # Node.js arbitrary code execution
            PolicyRule(
                binary="node",
                dangerous_args=["-e", "--eval"],
                description="node -e executes arbitrary JavaScript code",
                severity="critical",
            ),
            # tar checkpoint action exploit
            PolicyRule(
                binary="tar",
                dangerous_args=["--checkpoint-action=exec"],
                description="tar --checkpoint-action=exec can execute arbitrary commands",
                severity="critical",
            ),
            # Additional risky patterns (observe-only by default)
            PolicyRule(
                binary="curl",
                dangerous_args=["|"],  # piping curl output
                description="curl output piped to shell is risky",
                severity="high",
                action="warn",
            ),
            PolicyRule(
                binary="wget",
                dangerous_args=["-O", "-"],  # output to stdout
                description="wget to stdout may be piped to shell",
                severity="high",
                action="warn",
            ),
        ]
        return cls(rules=rules)

    def to_dict(self) -> dict:
        """Convert policy to dictionary."""
        return {
            "version": self.version,
            "rules": [
                {
                    "binary": r.binary,
                    "dangerous_args": r.dangerous_args,
                    "description": r.description,
                    "severity": r.severity,
                    "action": r.action,
                }
                for r in self.rules
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        """Create policy from dictionary."""
        rules = [
            PolicyRule(
                binary=r["binary"],
                dangerous_args=r["dangerous_args"],
                description=r.get("description", ""),
                severity=r.get("severity", "high"),
                action=r.get("action", "block"),
            )
            for r in data.get("rules", [])
        ]
        return cls(version=data.get("version", "1.0"), rules=rules)

    def save(self, path: Optional[Path] = None) -> None:
        """Save policy to file."""
        path = path or get_policy_file()
        path.parent.mkdir(parents=True, exist_ok=True)

        # Use JSON for simplicity (YAML would require external dep)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Policy":
        """Load policy from file, or return default if not found."""
        path = path or get_policy_file()

        if not path.exists():
            return cls.default()

        try:
            with open(path) as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception:
            return cls.default()

    def get_rules_for_binary(self, binary: str) -> list[PolicyRule]:
        """Get all rules that apply to a specific binary."""
        # Normalize binary name (handle paths)
        binary_name = Path(binary).name

        # Also handle python/python3 aliasing
        aliases = {
            "python3": ["python", "python3"],
            "python": ["python", "python3"],
        }

        names_to_match = aliases.get(binary_name, [binary_name])

        return [r for r in self.rules if r.binary in names_to_match]


@dataclass
class GuardState:
    """Persistent state for ward."""

    protected: bool = False
    enforce_mode: bool = False
    wrappers_installed: list[str] = field(default_factory=list)
    profile_modified: Optional[str] = None
    activated_at: Optional[str] = None

    def save(self) -> None:
        """Save state to file."""
        state_file = get_guard_dir() / "state.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)

        with open(state_file, "w") as f:
            json.dump(
                {
                    "protected": self.protected,
                    "enforce_mode": self.enforce_mode,
                    "wrappers_installed": self.wrappers_installed,
                    "profile_modified": self.profile_modified,
                    "activated_at": self.activated_at,
                },
                f,
                indent=2,
            )

    @classmethod
    def load(cls) -> "GuardState":
        """Load state from file."""
        state_file = get_guard_dir() / "state.json"

        if not state_file.exists():
            return cls()

        try:
            with open(state_file) as f:
                data = json.load(f)
            return cls(
                protected=data.get("protected", False),
                enforce_mode=data.get("enforce_mode", False),
                wrappers_installed=data.get("wrappers_installed", []),
                profile_modified=data.get("profile_modified"),
                activated_at=data.get("activated_at"),
            )
        except Exception:
            return cls()
