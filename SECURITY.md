# KIIBOT Security Policy

## Authorized Use Only

KIIBOT is designed exclusively for:

- **Authorized CTF competitions**
- **Cybersecurity laboratories**
- **Local vulnerable environments**
- **Penetration-testing labs with explicit authorization**
- **Digital forensics investigations**
- **Malware analysis in isolated labs**
- **Defensive security and incident response exercises**
- **Network analysis in authorized environments**
- **Reverse engineering of owned/authorized binaries**
- **Security research in authorized environments**

## Prohibited Use

KIIBOT must **NEVER** be used to:

- Attack unauthorized systems or networks
- Bypass anti-cheat systems in competitions
- Evade security monitoring or detection
- Establish persistence on unauthorized systems
- Steal credentials or personal data
- Deploy ransomware or destructive malware
- Scan arbitrary public infrastructure without authorization
- Stalk individuals or obtain private data
- Delete logs to cover unauthorized activity

## Security Guardrails

### Target Authorization
- All remote operations require explicit target authorization
- Default target allowlist: `127.0.0.1`, `localhost`
- Custom targets must be explicitly configured in `~/.kiibot/config.yaml`
- Aggressive scanning is never the default

### Data Protection
- No plaintext passwords, private keys, or API secrets are stored in the database
- All evidence is stored locally — nothing is uploaded externally
- Logs are stored locally with appropriate permissions

### Safe Execution
- Subprocess calls use argument arrays (no shell injection)
- All user input is sanitized before use in commands
- Timeouts and resource limits are enforced
- Destructive operations require explicit user confirmation

## Reporting Security Issues

If you discover a security vulnerability in KIIBOT, please report it responsibly:

1. **Do not** open a public issue
2. Contact the maintainers directly
3. Provide a detailed description of the vulnerability
4. Allow reasonable time for a fix before disclosure

## Compliance

Users are solely responsible for ensuring their use of KIIBOT complies with:

- Local laws and regulations
- Competition rules and terms of service
- Organizational security policies
- Network usage agreements
