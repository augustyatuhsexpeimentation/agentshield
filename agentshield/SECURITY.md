# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentShield, **please do not open a public issue.**

Instead, email: **your-email@example.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Security Best Practices for Users

- **Keep policies restrictive** — use `default_action: deny` in production
- **Never run AgentShield with elevated privileges** — it doesn't need root
- **Audit logs may contain sensitive metadata** — protect your `.jsonl` files
- **Review policy files before deploying** — use `agentshield validate`
- **Keep AgentShield updated** — detection patterns improve with each release

## Scope

AgentShield is a defense-in-depth layer. It is **not** a replacement for:
- Network-level security (firewalls, VPNs)
- Application-level auth (OAuth, RBAC)
- Infrastructure security (container isolation, least-privilege IAM)

Use AgentShield alongside your existing security stack, not instead of it.