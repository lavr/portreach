# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue for them.

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/lavr/portreach/security/advisories/new)**
(repository **Security** tab → *Report a vulnerability*).

We aim to acknowledge a report within a few days, agree on a disclosure
timeline, and credit reporters who wish to be named once a fix is released.

## Supported versions

This project is pre-1.0; only the latest released version receives security
fixes. Please upgrade to the most recent release before reporting.

## Scope notes

portreach intentionally makes outbound connections from every node where the
agent runs (an SSRF surface by design) and the optional SSO layer handles
cookies, tokens and allowlists. When reporting, please indicate whether the
issue concerns the agent probe path, the UI/auth layer, or the Helm chart.
