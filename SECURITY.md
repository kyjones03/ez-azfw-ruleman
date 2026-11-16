# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately through [GitHub security advisories](https://github.com/samsmith-MSFT/ez-azfw-manager/security/advisories/new). Include a description of the issue, steps to reproduce, and its potential impact. You should receive a response within a few business days, and we will keep you informed while a fix is prepared and released.

## Firewall logs and your data

- Firewall logs are read with your own Microsoft Entra sign-in. The app does not read, store or use Event Hub keys or connection strings. The setup wizard creates a **Send-only** access rule because Azure diagnostic settings require one, and never reads its keys. New namespaces are created with local (key) authentication disabled.
- Log rows are held **in memory only** (newest 5,000) and cleared on sign-out and directory switch. They are never written to disk, except by **Export CSV**, which saves the rows shown to a file you choose. Log content can include client IP addresses and destinations.
- Log text comes from the network, so it is treated as untrusted: control characters are made visible, and CSV cells that a spreadsheet would run as a formula are defused.
- Setting up logging and cleaning up deleted destinations change Azure directly, after a review that lists every change. They refuse to run if Azure changed since the review. A rule suggested from a denied flow in the logs is built from untrusted log text, which is checked first (IPv4 addresses, plain host names, valid ports), and it only enters your draft: nothing reaches Azure until you review and commit it.
