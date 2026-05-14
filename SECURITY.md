# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Email **sec.gary@gmail.com** with:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The version(s) affected

You will receive an acknowledgement within 2 business days. If the report is confirmed, a fix will be prepared and released as soon as practical, and you will be credited in the release notes unless you prefer otherwise.

## Scope

Gate is a local PII-filtering proxy. Reports in scope include:

- False-negative redaction bugs where PII reaches the model context
- Bypass techniques that defeat Gate 1 or Gate 2
- Vulnerabilities in the hook path that allow silent passthrough of interceptable commands
- Issues in `gate init` / `gate uninstall` that affect files outside the gate config directory

Out of scope: social engineering, physical access, vulnerabilities in upstream tools gate wraps (psql, curl, etc.), or issues that require the attacker to already have write access to `~/.config/gate/`.
