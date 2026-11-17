# Security policy

## Supported versions

Only the latest release receives security fixes.

## Development dependency advisory status (2026-11-17)

- The affected modern `glob` and `minimatch` dependency chains are overridden to patched versions (`glob` 14.0.4 and `minimatch` 11.0.6). Legacy major versions outside these advisories' affected ranges are retained for API compatibility.
- **Unresolved:** GHSA-fc5q-39xc-vjpf affects every available `picomatch` release through 4.0.7. No patched release is published. This is a high-severity regular-expression denial of service in development tooling, not a production dependency. Do not feed untrusted glob patterns into build, watch or test tooling. Reassess and remove this exception when an upstream patch is available; this is not a clean vulnerability audit.
- The lockfile omits registry-specific tarball URLs using npm's supported `omit-lockfile-registry-resolved` mode. Versions and integrity checks remain pinned; installs resolve tarballs through the caller's configured registry.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately through [GitHub security advisories](https://github.com/samsmith-MSFT/ez-azfw-manager/security/advisories/new). Include a description of the issue, steps to reproduce, and its potential impact. You should receive a response within a few business days, and we will keep you informed while a fix is prepared and released.

## Firewall logs and your data

- Firewall logs are read with your own Microsoft Entra sign-in. The app does not read, store or use Event Hub keys or connection strings. The setup wizard creates a **Send-only** access rule because Azure diagnostic settings require one, and never reads its keys. New namespaces are created with local (key) authentication disabled.
- Log rows are held **in memory only** (newest 5,000) and cleared on sign-out and directory switch. They are never written to disk, except by **Export CSV**, which saves the rows shown to a file you choose. Log content can include client IP addresses and destinations.
- Log text comes from the network, so it is treated as untrusted: control characters are made visible, and CSV cells that a spreadsheet would run as a formula are defused.
- Setting up logging and cleaning up deleted destinations change Azure directly, after a review that lists every change. They refuse to run if Azure changed since the review. A rule suggested from a denied flow in the logs is built from untrusted log text, which is checked first (IPv4 addresses, plain host names, valid ports), and it only enters your draft: nothing reaches Azure until you review and commit it.
