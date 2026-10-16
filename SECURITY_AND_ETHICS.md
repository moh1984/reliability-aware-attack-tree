# Security & Ethics Statement

This package contains offensive security payloads (SQL injection, command
injection, XSS, path traversal, CSRF) used solely to measure a web-application
firewall's attenuation of known-vulnerable, **intentionally vulnerable** targets
in an **isolated, self-hosted** environment.

## Scope and safe use

- All targets are intentionally vulnerable teaching applications: **DVWA** and
  **OWASP Juice Shop**, run as local Docker containers.
- No real user data, no production systems, and no third-party systems are in
  scope at any point.
- All traffic is confined to `localhost` on the operator's own machine.
- The payloads are standard, publicly documented test vectors; none are novel
  exploits or weaponized against real systems.

## Responsible use

Do **not** run these scripts against any system you do not own or lack explicit
written authorization to test. Unauthorized scanning or exploitation of systems
is illegal in most jurisdictions. This package is released for reproducible
academic research and defensive evaluation only.

## Defensive value

The command-injection result localizes a concrete OWASP CRS coverage gap
(at paranoia level 1 the tested `id` command was allowed across multiple separators, while the `echo` payloads that succeeded undefended were blocked; the `whoami`/`uname` requests were also rejected with HTTP 403 but did not succeed undefended, so they are excluded from d). Defenders can use the
methodology to measure their own WAF's per-mechanism attenuation and close such
gaps.
