# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest release on the `master` branch receives security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in netsec-toolkit, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

**Email:** [bishitaofik@gmail.com](mailto:bishitaofik@gmail.com)

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected component(s) (port scanner, network mapper, vulnerability checker, etc.)
- Any proof-of-concept code or output, if available

## Response Timeline

| Action                     | Timeframe       |
|----------------------------|-----------------|
| Acknowledgment of report   | 48 hours        |
| Initial assessment         | 5 business days |
| Patch or mitigation issued | 30 days         |
| Public disclosure           | After patch     |

We will coordinate disclosure timing with the reporter. Credit will be given unless anonymity is requested.

## Scope

The following are **in scope** for security reports:

- Vulnerabilities in scanning modules (port scanner, network mapper, vulnerability checker)
- Command injection or argument injection via user-supplied input
- Unsafe handling of network responses (e.g., buffer issues from banner grabbing)
- Dependencies with known CVEs that affect this toolkit
- Information disclosure through logging or error output

The following are **out of scope**:

- Issues that require physical access to the machine running the toolkit
- Denial-of-service against the toolkit itself (it is a CLI tool, not a service)
- Findings from scanning third-party targets (this is a tool, not a service)

## Authorized Use Reminder

This toolkit is intended for **authorized security testing only**. Users are responsible for obtaining proper written authorization before scanning any target. The maintainers are not responsible for misuse. See the [LICENSE](LICENSE) for details.
