# Security Policy

## Intended use

PromptHound generates attack-shaped content and sends injection payloads. It is
intended **only** for authorized testing — AI features in scope for a bug-bounty
program, a pentest with a signed statement of work, or systems you own. Using it
against targets without explicit permission, or to deceive or defraud real users,
may be illegal.

## Reporting a vulnerability

If you find a security issue **in PromptHound itself** (for example, a path
traversal in the output writer, or unsafe handling of a probe response), please
report it privately rather than opening a public issue:

- Open a [GitHub Security Advisory](https://github.com/R00t3dbyFa17h/PromptHound/security/advisories/new), or
- Contact the maintainer **R00t3dbyFa17h** via GitHub.

Include a description, affected version, and a minimal reproduction. You'll get
an acknowledgement, and a fix will be coordinated before public disclosure.

## Supported versions

The latest released version on the `main` branch is supported.
