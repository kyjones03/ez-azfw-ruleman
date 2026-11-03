# EZ AzFW Rule Manager

A cross-platform desktop app for managing [Azure Firewall](https://learn.microsoft.com/azure/firewall/overview) policy rules with a safe **draft → review → commit** workflow.

Instead of editing rules live in the Azure portal, you stage changes locally as a _candidate_, review the risk and the exact diff, and then commit them to Azure in one step — with a shared history of every commit.

[![Latest release](https://img.shields.io/github/v/release/samsmith-MSFT/ez-azfw-ruleman?label=download&sort=semver)](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases/latest)
[![CI](https://github.com/samsmith-MSFT/ez-azfw-ruleman/actions/workflows/ci.yml/badge.svg)](https://github.com/samsmith-MSFT/ez-azfw-ruleman/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**[⬇ Download the latest version](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases/latest)** for Windows, macOS or Linux. Nothing to install: download it and run it.

**Jump to:** [Features](#features) · [Download](#download-and-run) · [Signing in](#signing-in) · [Permissions](#required-azure-permissions) · [Data storage](#where-your-data-is-stored) · [Code signing policy](#code-signing-policy) · [Development](#development) · [Releasing](#releasing) · [Contributing](#contributing) · [Disclaimer](#disclaimer) · [License](#license)

## Features

- **Sign in your way** — interactive browser sign-in (Microsoft Entra ID via MSAL) or reuse an existing Azure CLI session. Switch between directories (tenants) you have access to.
- **Discovery** — finds Azure Firewalls and Firewall Policies across all your subscriptions using Azure Resource Graph.
- **Rule editing** — create and edit rule collection groups, rule collections, and DNAT, network, and application rules, with lookups for IP Groups, service tags, FQDN tags, and web categories.
- **Draft and commit** — changes are staged in a local candidate that survives restarts. Nothing is sent to Azure until you commit.
- **Review** — see a per-group diff and a risk assessment (e.g. overly broad sources, destinations, or ports) before committing. Concurrent changes made in Azure are detected using ETags.
- **Policy snapshots and rollback** — dated snapshots are captured automatically whenever a policy is loaded, updated, or committed, with collapsible Rule Collection Group → Rule Collection → Rules views and one-click rollback to any former state.
- **Commit history** — every commit is saved to the same shared Azure Blob Storage account as the snapshots, so you and your teammates can see who made what change and its outcome. Commits that couldn't be saved there still show on the device that made them.
- **Flow tester** — check which rule would match a given source, destination, protocol, and port. Optionally pick the destination's web category (from the portal's Web Category Check) so web category rules can be decided.
- **CSV import and export** — bulk-edit rules in a spreadsheet and bring them back in.
- **Deploy new firewalls** — a guided wizard deploys a new Azure Firewall and Firewall Policy into a new or existing virtual network, or a Virtual WAN hub, using an ARM deployment.

## Download and run

Download the file for your platform from the [latest release](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases/latest). Every build is portable: there is nothing to install. Just download it and run it.

| Platform              | File                                              | How to run                                    |
| --------------------- | ------------------------------------------------- | --------------------------------------------- |
| Windows (x64)         | `ez-azfw-ruleman-<version>-win-x64.exe`           | Double-click it                               |
| Windows (Arm64)       | `ez-azfw-ruleman-<version>-win-arm64.exe`         | Double-click it                               |
| macOS (Apple silicon) | `ez-azfw-ruleman-<version>-mac-arm64.zip`         | Unzip, then open **EZ AzFW Rule Manager.app** |
| macOS (Intel)         | `ez-azfw-ruleman-<version>-mac-x64.zip`           | Unzip, then open **EZ AzFW Rule Manager.app** |
| Linux (x64)           | `ez-azfw-ruleman-<version>-linux-x86_64.AppImage` | `chmod +x` it, then run it                    |

The Windows executable unpacks itself to a temporary folder each time it starts, so it takes a few seconds longer to open than an installed app. Your drafts, history and sign-in are kept in your user profile (see [Where your data is stored](#where-your-data-is-stored)), not next to the executable, so you can move or replace it with a newer version freely.

### First launch on each OS

Release builds are not code-signed unless the maintainer has configured signing certificates (see the [code signing policy](#code-signing-policy)), so your OS may warn you the first time you run the app.

- **Windows SmartScreen** — if you see "Windows protected your PC", select **More info** → **Run anyway**.
- **macOS Gatekeeper** — if macOS says the app "cannot be opened" or "is damaged", right-click it and choose **Open**, or go to **System Settings** → **Privacy & Security** and select **Open Anyway**. Alternatively, remove the quarantine flag:

  ```sh
  xattr -dr com.apple.quarantine "EZ AzFW Rule Manager.app"
  ```

- **Linux** — AppImages need FUSE 2 (`sudo apt install libfuse2` on Ubuntu 22.04+). On Ubuntu 23.10 and later, AppArmor blocks the Chromium sandbox for apps outside system paths; if the app exits immediately, allow it with an AppArmor profile (`/etc/apparmor.d/ez-azfw-ruleman`):

  ```text
  abi <abi/4.0>,
  include <tunables/global>
  profile ez-azfw-ruleman /path/to/ez-azfw-ruleman-*.AppImage flags=(unconfined) {
    userns,
  }
  ```

  then run `sudo apparmor_parser -r /etc/apparmor.d/ez-azfw-ruleman`.

## Signing in

| Option         | How it works                                                                                                                                        |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-in window | Opens a sign-in window in the app with an account picker, so you choose which account to use. Supports MFA.                                         |
| Browser (MSAL) | Opens your default browser (with its current profile) to sign in. Use it when Conditional Access requires a compliant device or managed browser.    |
| Azure CLI      | Uses the account you are signed in to with `az login`. Requires the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) on `PATH`. |

By default, browser sign-in uses the Azure CLI's public client ID, so no app registration is needed. To use your own Entra app registration, set the `EZAZFW_CLIENT_ID` environment variable (a public client with `http://localhost` as a redirect URI). Set `EZAZFW_TENANT_ID` to pre-select a directory. The app deliberately ignores `AZURE_CLIENT_ID` and `AZURE_TENANT_ID`, which other tools often set for their own app registrations.

The app only requests the Azure Resource Manager scope (`https://management.azure.com/.default`); it can do nothing your account cannot already do in Azure.

## Required Azure permissions

Access is governed by Azure RBAC on your own account:

| Task                                                              | Minimum role                                                                                                                                                                 |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Browse firewalls, policies, rules, and IP Groups                  | **Reader** on the subscriptions or resource groups                                                                                                                           |
| Commit rule changes                                               | **Network Contributor** on the firewall policy (or a custom role with `Microsoft.Network/firewallPolicies/ruleCollectionGroups/read` and `/write`)                           |
| Reference IP Groups in rules                                      | `Microsoft.Network/ipGroups/join/action` (included in Network Contributor) on the IP Groups                                                                                  |
| Deploy a new firewall                                             | **Contributor** (or Network Contributor plus deployment rights) on the target resource group; on the subscription if the wizard creates new resource groups                  |
| View, save, and roll back policy snapshots and the commit history | **Storage Blob Data Contributor** on the shared storage account (it covers the snapshot and commit-history containers). Owner and Contributor don't include blob data access |
| Create a snapshot storage account in the app                      | **Contributor** to create it, plus **Owner** or **User Access Administrator** so the app can assign you Storage Blob Data Contributor on it                                  |

## Where your data is stored

Everything the app keeps is stored locally in your user profile, in an `ez-azfw-ruleman` folder:

| OS      | Location                                        |
| ------- | ----------------------------------------------- |
| Windows | `%APPDATA%\ez-azfw-ruleman`                     |
| macOS   | `~/Library/Application Support/ez-azfw-ruleman` |
| Linux   | `~/.config/ez-azfw-ruleman`                     |

- `ez-azfw-ruleman-state.json` — draft (candidate) changes, your recent commits, and storage settings. Policy snapshots and the shared commit history live in Azure Blob Storage, not on disk.
- `msal-cache.bin` — the sign-in token cache, **encrypted** with the OS key store (DPAPI on Windows, Keychain on macOS, libsecret on Linux). If no secure key store is available (e.g. Linux without a keyring), tokens are never written to disk and you sign in again each session.

Delete the folder to reset the app. No telemetry is collected; the app talks only to Microsoft Entra ID, Azure Resource Manager and the Azure Blob Storage account you choose for snapshots and commit history.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

> **Status:** Windows signing is applied for but not yet active, so Windows builds are currently unsigned. This note will be removed once signing is live.

- **Scope:** only the Windows executables (`.exe`) in [GitHub releases](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases), built from this repository by the [Release workflow](.github/workflows/release.yml). Nothing built elsewhere is signed.
- **Authors, reviewers and approvers:** [samsmith-MSFT](https://github.com/samsmith-MSFT). Every release needs manual approval before it is signed.
- **Privacy policy:** this program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it. It sends nothing to the maintainers. Its only network connections are to Microsoft Entra ID, Azure Resource Manager and the Azure Blob Storage account you configure, using your own sign-in (see [Where your data is stored](#where-your-data-is-stored)).
- **No system changes:** the app is portable. It doesn't install anything or change system settings, and you uninstall it by deleting the file and the data folder above.

## Development

Requirements: [Node.js](https://nodejs.org/) 22 or later and npm. `npm run dist` builds for the OS it runs on (Windows, macOS or Linux); use CI to build the others.

```sh
git clone https://github.com/samsmith-MSFT/ez-azfw-ruleman.git
cd ez-azfw-ruleman
npm ci
npm start
```

Set `EZAZFW_DEVTOOLS=1` to open the developer tools on start in development.

### Scripts

| Script              | Description                                                                        |
| ------------------- | ---------------------------------------------------------------------------------- |
| `npm start`         | Run the app in development with hot reload                                         |
| `npm run lint`      | Lint with oxlint and check formatting with oxfmt                                   |
| `npm run lint:fix`  | Fix lint issues and format                                                         |
| `npm run typecheck` | Type-check with TypeScript                                                         |
| `npm test`          | Run unit tests with Vitest                                                         |
| `npm run verify`    | Lint, type-check, and test (what CI runs)                                          |
| `npm run package`   | Build the app for the current platform into `out/`                                 |
| `npm run dist`      | Build the portable executable into `out/release/` (add `-- --arch x64` or `arm64`) |
| `npm run icons`     | Regenerate app icons from `assets/icons/logo.svg`                                  |

### Project structure

```text
assets/icons/        App icon sources and generated .ico/.icns/.png
scripts/             Build helper scripts (portable release build, icon generation)
src/
  main.ts            Electron main process entry point
  preload.ts         Preload script exposing the IPC bridge to the renderer
  main/              Main process: auth, Azure clients, draft store, deployments, IPC
  renderer/          React UI (views and components)
  shared/            Pure logic shared by both processes (rules, diff/merge, risk, CSV, flow testing)
forge.config.mts     Electron Forge build configuration (Vite, fuses, signing)
electron-builder.yml Portable executable targets (Windows .exe, Linux AppImage, macOS zip)
vite.*.config.mts    Vite build configuration for main, preload, and renderer
```

## Releasing

1. Add a `## [1.2.3] - YYYY-MM-DD` section to `CHANGELOG.md` and bump the version: `npm version <major|minor|patch> --no-git-tag-version`.
2. Commit, then tag and push: `git tag v1.2.3 && git push origin main v1.2.3`.
3. The [Release workflow](.github/workflows/release.yml) builds portable executables for Windows (x64 and Arm64), macOS (arm64 and x64) and Linux (x64) into a draft release. Once **every** build succeeds, it adds `SHA256SUMS.txt`, writes the release notes (a download table plus that version's CHANGELOG section, from [`.github/release-notes.md`](.github/release-notes.md)), and publishes the release as **Latest**.

The tag must match the `version` in `package.json`. If a build fails, the release stays a draft. Fix the problem, then re-run the failed jobs (or run the workflow manually with the tag).

### Code signing (optional)

Builds are unsigned unless these repository secrets are set:

| Secret                                                     | Purpose                                                          |
| ---------------------------------------------------------- | ---------------------------------------------------------------- |
| `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`          | Base64-encoded Developer ID Application `.p12` and its password  |
| `APPLE_SIGNING_IDENTITY`                                   | Signing identity, e.g. `Developer ID Application: Name (TEAMID)` |
| `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` | Notarization credentials (used only when the app is signed)      |
| `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD`      | Base64-encoded Authenticode `.pfx` and its password              |

Locally, the same settings are read from environment variables (`APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD` or `APPLE_PASSWORD`, `APPLE_TEAM_ID`, `WINDOWS_CERTIFICATE_FILE`, `WINDOWS_CERTIFICATE_PASSWORD`).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## Disclaimer

This software is provided "as is", without warranty of any kind, and you use it at your own risk. It changes Azure Firewall policies, which can affect network traffic and security. Review every change before you commit it, test in a non-production environment first, and keep your own backups or snapshots. The authors aren't liable for any outage, data loss, security exposure or other damage that results from using it. See the [LICENSE](LICENSE) for the full terms.

## License

[MIT](LICENSE) © 2026 samsmith-MSFT

This is not an official Microsoft product. Azure and Azure Firewall are trademarks of Microsoft Corporation.
