# Security Policy

`secrets-guard` is a security tool, so we take vulnerabilities seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, or email the maintainers at `security@<your-domain>`
(replace with your real contact before publishing).

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal hook payload or prompt is ideal).
- Any suggested remediation.

We aim to acknowledge reports within 3 business days.

## Scope and known limitations

secrets-guard is a **client-side** control and one layer of defense in depth.
Be aware:

- It is **best-effort detection**. No regex/NER set catches every secret; tune
  `custom_patterns_path` for your environment.
- Hooks run on the developer's machine. A user with local admin rights can
  disable them. For a non-bypassable control, enforce the plugin via
  `managed-settings.json` and pair it with network-level DLP.
- Claude Code 2.1.x does not honor client-side rewriting of tool **output**, so
  non-Bash tool output containing a secret is **withheld**, not redacted. Inline
  redaction across all surfaces requires a network DLP gateway.
- Resolved secret values necessarily reach the local process that executes the
  tool. secrets-guard ensures the **model** never sees them; it does not encrypt
  them on the host.

Treat secrets-guard as a strong guardrail, not a guarantee.
