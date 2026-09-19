# Security Policy

## Reporting a vulnerability
Open a private security advisory via GitHub **Security - Advisories**, or email the maintainer. Do NOT open public issues for vulnerabilities.

## Design guarantees
- Path containment on every file operation (symlink-aware)
- Credential redaction applied to logs, reports, JSON envelopes
- Archive extraction refuses traversal/symlinks/bombs
- Subprocess execution: argument lists only, never shell strings

## Known accepted risks
See "Known limitations" in README.md.
