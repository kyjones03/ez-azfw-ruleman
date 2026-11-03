# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Updated React to 19, TypeScript to 7 and the formatter (oxfmt), and the GitHub Actions used by CI and releases to v7.

## [1.3.0] - 2026-11-03

### Added

- **Shared commit history.** Every commit is saved to the same Azure Blob Storage account as the snapshots, so you and your teammates can see who made what change. It uses its own blob container, which must be different from the snapshot container: the setup form checks this, and the app refuses to save or read history from the snapshot container. Commits that couldn't be saved there still show on the device that made them, marked "This device only".
- The "Rule collection groups" panel on the Rules page can be collapsed to give the rules more room; the app remembers your choice.
- Creating a snapshot storage account now assigns you the **Storage Blob Data Contributor** role on it, with a spinner on the button while it deploys. If you can't create role assignments, a notice on the Snapshots tab tells you to assign yourself that role before you can view snapshots.
- Choosing an existing storage account shows a banner explaining that you need blob data access (Storage Blob Data Contributor) on it.
- **Flow tester web categories.** Azure has no API that maps a site to its web category, so the Flow tester has an optional "Destination web categories" field. Pick the category you found with Web Category Check in the portal and web category rules are matched against it instead of showing as "unsure".

### Changed

- Snapshot blobs are now read and written with your own Azure sign-in (Microsoft Entra ID) instead of storage account keys.
- A commit's snapshot is also saved when the commit finishes after the app was restarted. If saving it fails, the commit is still recorded and you're told the snapshot wasn't saved.
- Committing now checks that you can access snapshot storage before anything is written to Azure.
- The Rules page no longer shows "Committing N changes to Azure…" under the group name; the progress bar at the bottom of the app already shows it.

### Fixed

- Blob access failures now report Azure's error code and say whether the cause is a missing role, storage networking (firewall or disabled public access), or a rejected sign-in, instead of always asking you to assign a role.
- The Snapshots tab failed with a Resource Graph `BadRequest` when listing storage accounts, and kept showing a loading spinner next to the error.
- Errors loading storage configuration, subscriptions, regions or snapshots are now shown instead of an endless spinner, a disabled button, or a misleading "no snapshots" message.
- Snapshot lists now include every page of results, always show each policy's newest snapshot, and skip malformed snapshot files instead of crashing the view.

## [1.2.0] - 2026-11-02

### Added

- Firewall policy **Snapshots** tab backed by centralized geo-redundant Azure Blob Storage (`Standard_GRS` with blob soft delete, container soft delete, and blob versioning enabled by default) and tenant-wide auto-discovery.
- Cumulative commit-only policy snapshots that capture the full policy state once per commit, with nested Rule Collection Group → Rule Collection → Rules dropdowns and one-click rollback staging.

## [1.1.1] - 2026-10-30

### Fixed

- Sign-in failed with AADSTS650057 when another tool had set `AZURE_CLIENT_ID`. The app now reads its own `EZAZFW_CLIENT_ID` and `EZAZFW_TENANT_ID` variables instead of `AZURE_CLIENT_ID` and `AZURE_TENANT_ID`.

## [1.1.0] - 2026-10-30

### Changed

- Microsoft account sign-in now opens in an app sign-in window with an account picker, instead of the default browser profile. Default-browser sign-in is still available.

## [1.0.0] - 2026-10-29

Initial public release.

### Added

- Sign-in with a browser (Microsoft Entra ID via MSAL) or an existing Azure CLI session, with directory (tenant) switching.
- Discovery of Azure Firewalls and Firewall Policies across subscriptions using Azure Resource Graph.
- Editing of rule collection groups, rule collections, and DNAT, network, and application rules, with IP Group, service tag, FQDN tag, and web category lookups.
- Draft (candidate) workflow: changes are staged locally and persist across restarts until committed.
- Risk review and per-group diffs before committing, with detection of concurrent changes made in Azure.
- Local commit history.
- Flow tester to find which rule matches a given flow.
- CSV import and export of rules.
- Wizard to deploy a new Azure Firewall and Firewall Policy.
- Encrypted, OS key store–backed token cache.
- Portable, no-install executables for Windows (x64 and Arm64 `.exe`), macOS (zipped `.app`, arm64 and x64), and Linux (x64 AppImage).

[Unreleased]: https://github.com/samsmith-MSFT/ez-azfw-ruleman/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/samsmith-MSFT/ez-azfw-ruleman/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/samsmith-MSFT/ez-azfw-ruleman/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/samsmith-MSFT/ez-azfw-ruleman/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/samsmith-MSFT/ez-azfw-ruleman/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases/tag/v1.0.0
