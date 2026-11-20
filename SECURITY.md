# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

IronyKeys handles encryption keys, volume headers, and privileged Linux block-device operations (`dm-crypt`, `losetup`, `mount`). Please do **not** open public GitHub issues for security vulnerabilities.

Instead, report vulnerabilities privately via GitHub Security Advisories (**Security → Advisories → Report a vulnerability**) or email `zk@hexawulf.dev` with:

- A description of the vulnerability and its impact
- Reproduction steps or a minimal proof of concept
- Affected IronyKeys version (`ironykeys version`), OS, and Go version

You can expect an initial acknowledgement within 72 hours.

## Security Model & Known Limits

See [README.md — Security model and limits](README.md#%EF%B8%8F-security-model-and-limits) and [SPEC.md](SPEC.md) for the documented threat model, cryptographic profile (`AES-256-XTS`, `PBKDF2-HMAC-SHA512`), and non-goals (e.g., XTS provides confidentiality without integrity/tamper detection).
