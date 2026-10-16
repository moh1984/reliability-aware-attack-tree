# Image digests for this run

> **STATUS: TEMPLATE — NOT YET GENERATED.**
> This file is shipped as a placeholder so that the directory listing in `README.md`
> is complete. The digests below are deliberately left blank: a digest is only
> meaningful if it is read off the machine that actually produced the results, and
> no digest was recorded at the time of the published run.
>
> **To fill it in**, on the machine that runs the experiments:
>
> ```powershell
> docker compose up -d
> .\scripts\02_zap_scan.ps1        # pulls the ZAP image
> .\scripts\15_record_digests.ps1  # overwrites this file with the real digests
> ```
>
> Then copy each digest into `.env` so the environment is pinned, e.g.
> `DVWA_IMAGE=vulnerables/web-dvwa@sha256:<digest>`.

| Variable | Tag used | RepoDigest |
|---|---|---|
| `DVWA_IMAGE` | `vulnerables/web-dvwa:latest` | _(run `15_record_digests.ps1`)_ |
| `JUICESHOP_IMAGE` | `bkimminich/juice-shop:latest` | _(run `15_record_digests.ps1`)_ |
| `WAF_IMAGE` | `owasp/modsecurity-crs:apache` | _(run `15_record_digests.ps1`)_ |
| `ZAP_IMAGE` | `ghcr.io/zaproxy/zaproxy:stable` | _(run `15_record_digests.ps1`)_ |

## Engine

The published run used Docker engine 29.6.2 with Compose v5.3.1 on Windows with the
WSL2 backend. `15_record_digests.ps1` records the engine and Compose versions of
*your* run here, replacing this paragraph.

## Why this matters

The four tags above are floating: `latest`, `stable` and `apache` are reassigned
upstream over time. A re-run months later may therefore pull a different build —
most consequentially a newer OWASP CRS ruleset, which can shift individual
per-payload outcomes by ±1 and hence move a graded *d* slightly. `README.md`
section 6 notes this explicitly. Pinning by digest removes that drift; until this
file is filled in, the package reproduces the *qualitative* pattern (injection
attenuated, logic and off-path unattenuated) but not necessarily every integer.
