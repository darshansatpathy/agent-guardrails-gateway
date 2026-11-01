# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/darshansatpathy/agent-guardrails-gateway/security/advisories/new)
for this repository. You should get an acknowledgement within three working days.

## Scope

This project is a reference implementation. The [threat model](docs/threat-model.md)
lists what it is designed to defend against and what is deliberately out of scope.

## Operating it safely

- Set `AGGW_GRANT_SECRET` and `AGGW_AUDIT_KEY` from a secret manager. Never rely on the
  ephemeral dev keys generated when they are missing.
- Replace the admin bearer token with your identity provider before production use.
- Restrict write access to the audit log and export its head hash regularly.
