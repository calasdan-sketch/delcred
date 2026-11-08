# Security policy

## Reporting a vulnerability

Email **office@calasautomations.com** with "delcred security" in the subject.
Please include the version, a description, and steps to reproduce. Do not open
a public issue for an unfixed vulnerability.

## Advisories

| Version | Issue | Fixed in |
|---|---|---|
| 0.2.0 | A trusted external IdP could sign delegation and agent tokens that bypassed policy. Affects deployments with at least one entry in `trusted_issuers`. | 0.2.1 |

Details: see `CHANGELOG.md` (0.2.1).

## Supported versions

Only the latest release receives security fixes.
