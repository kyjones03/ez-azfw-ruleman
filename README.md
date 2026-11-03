# EZ AzFW Rule Manager

A cross-platform desktop app for managing [Azure Firewall](https://learn.microsoft.com/azure/firewall/overview) policy rules with a safe **draft → review → commit** workflow.

Instead of editing rules live in the Azure portal, you stage changes locally as a _candidate_, review the risk and the exact diff, and then commit them to Azure in one step, with a shared history of every commit.

[![Latest release](https://img.shields.io/github/v/release/samsmith-MSFT/ez-azfw-ruleman?label=download&sort=semver)](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases/latest)
[![CI](https://github.com/samsmith-MSFT/ez-azfw-ruleman/actions/workflows/ci.yml/badge.svg)](https://github.com/samsmith-MSFT/ez-azfw-ruleman/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**[⬇ Download the latest version](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases/latest)** for Windows, macOS or Linux. Nothing to install: download it and run it.

**Jump to:** [Features](#features) · [Download](#download-and-run) · [Signing in](#signing-in) · [Permissions](#required-azure-permissions) · [Data storage](#where-your-data-is-stored) · [Code signing policy](#code-signing-policy) · [Development](#development) · [Releasing](#releasing) · [Contributing](#contributing) · [Disclaimer](#disclaimer) · [License](#license)

## Features

- **Sign in your way**: interactive browser sign-in (Microsoft Entra ID via MSAL) or reuse an existing Azure CLI session. Switch between directories (tenants) you have access to.
- **Discovery**: finds Azure Firewalls and Firewall Policies across all your subscriptions using Azure Resource Graph.
- **Rule editing**: create and edit rule collection groups, rule collections, and DNAT, network, and application rules, with lookups for IP Groups, service tags, FQDN tags, and web categories.
- **Draft and commit**: changes are staged in a local candidate that survives restarts. Nothing is sent to Azure until you commit.
- **Review**: see a per-group diff and a risk assessment (e.g. overly broad sources, destinations, or ports) before committing. Concurrent changes made in Azure are detected using ETags.
- **Policy snapshots and rollback**: a full snapshot of the policy is saved to shared Azure Blob Storage each time you commit, with collapsible Rule Collection Group → Rule Collection → Rules views and one-click rollback to any former state.
- **Commit history**: every commit is saved to the same shared Azure Blob Storage account as the snapshots, so you and your teammates can see who made what change and its outcome. Commits that couldn't be saved there still show on the device that made them.
- **Flow tester**: check which rule would match a given source, destination, protocol, and port. Optionally pick the destination's web category (from the portal's Web Category Check) so web category rules can be decided.
- **CSV import and export**: bulk-edit rules in a spreadsheet and bring them back in.
- **Deploy new firewalls**: a guided wizard deploys a new Azure Firewall and Firewall Policy into a new or existing virtual network, or a Virtual WAN hub, using an ARM deployment.

## Download and run

Download the file for your platform from the [latest release](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases/latest). On Windows, the **installer** adds Start menu and desktop shortcuts and an uninstaller. The Windows portable file and the macOS and Linux builds need no installation: download and run them.

| Platform                   | File                                              | How to run                                    |
| -------------------------- | ------------------------------------------------- | --------------------------------------------- |
| Windows (x64), installer   | `ez-azfw-ruleman-<version>-win-x64-setup.exe`     | Run it and follow the prompts                 |
| Windows (Arm64), installer | `ez-azfw-ruleman-<version>-win-arm64-setup.exe`   | Run it and follow the prompts                 |
| Windows (x64), portable    | `ez-azfw-ruleman-<version>-win-x64.exe`           | Double-click it                               |
| Windows (Arm64), portable  | `ez-azfw-ruleman-<version>-win-arm64.exe`         | Double-click it                               |
| macOS (Apple silicon)      | `ez-azfw-ruleman-<version>-mac-arm64.zip`         | Unzip, then open **EZ AzFW Rule Manager.app** |
| macOS (Intel)              | `ez-azfw-ruleman-<version>-mac-x64.zip`           | Unzip, then open **EZ AzFW Rule Manager.app** |
| Linux (x64)                | `ez-azfw-ruleman-<version>-linux-x86_64.AppImage` | `chmod +x` it, then run it                    |

The installer is per-user, so it doesn't need administrator rights, and you can remove it from **Settings** → **Apps** like any other app. Uninstalling keeps your data. The portable Windows executable unpacks itself to a temporary folder when it starts, so it takes a few seconds longer to open. Your drafts, history and sign-in are kept in your user profile (see [Where your data is stored](#where-your-data-is-stored)), not next to the executable, so you can switch between the installer and portable builds, or replace either with a newer version, freely.

### First launch on each OS

Release builds are not code-signed unless the maintainer has configured signing certificates (see the [code signing policy](#code-signing-policy)), so your OS may warn you the first time you run the app.

- **Windows SmartScreen**: if you see "Windows protected your PC", select **More info** → **Run anyway**.
- **macOS Gatekeeper**: if macOS says the app "cannot be opened" or "is damaged", right-click it and choose **Open**, or go to **System Settings** → **Privacy & Security** and select **Open Anyway**. Alternatively, remove the quarantine flag:

  ```sh
  xattr -dr com.apple.quarantine "EZ AzFW Rule Manager.app"
  ```

- **Linux**: AppImages need FUSE 2 (`sudo apt install libfuse2` on Ubuntu 22.04+). On Ubuntu 23.10 and later, AppArmor blocks the Chromium sandbox for apps outside system paths; if the app exits immediately, allow it with an AppArmor profile (`/etc/apparmor.d/ez-azfw-ruleman`):

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

The app keeps data in three places: on your device, in your own Azure storage account, and in files you choose to save.

### On your device

Everything the app saves locally goes in your user profile, in an `ez-azfw-ruleman` folder. It is not next to the executable, so you can move or replace the app freely.

| OS      | Location                                        |
| ------- | ----------------------------------------------- |
| Windows | `%APPDATA%\ez-azfw-ruleman`                     |
| macOS   | `~/Library/Application Support/ez-azfw-ruleman` |
| Linux   | `~/.config/ez-azfw-ruleman`                     |

- `ez-azfw-ruleman-state.json`: your draft (candidate) changes, including a copy of each group as it was when you started editing; your 200 most recent commits; commits still running; the list of firewalls you manage; which storage account and containers hold your snapshots; your last sign-in (user name and directory); and which sign-in to restore at startup (the method and account ID, never a password or token).
- `msal-cache.bin`: the sign-in token cache, **encrypted** with the OS key store (DPAPI on Windows, Keychain on macOS, libsecret on Linux). If no secure key store is available (e.g. Linux without a keyring), tokens are never written to disk and you sign in again each session. Signing out deletes it.
- Browser-engine data that the app's window creates automatically: your interface preferences and recent activity list (panel layout, filters, auto-refresh interval, recent commits and deployments) in local storage, the sign-in window's cookies and remembered accounts in a `Partitions` folder (cleared when you sign out), and ordinary cache files.

With Azure CLI sign-in the app saves no token of its own: it asks the CLI for one when needed.

### In your Azure storage account

Policy snapshots and the shared commit history are stored in an Azure Blob Storage account you choose or create in the app, not on your device.

- A full snapshot of the policy's rules is uploaded each time a commit finishes, to the `ez-azfw-snapshots` container by default. Commit history goes to a separate container, `ez-azfw-history` by default.
- You must configure this storage before you can commit, because every commit saves a snapshot.
- The account is tagged `ez-azfw-ruleman-snapshots = true`, so your teammates' installations find it automatically.
- The app reads and writes the blobs with your own Microsoft Entra sign-in, not storage account keys (see [Required Azure permissions](#required-azure-permissions)).

### Files you save

CSV exports go where you choose in the save dialog (the Documents folder by default). The Windows executable also unpacks itself to an `ez-azfw-ruleman` folder in your temporary files.

To reset the app, sign out and delete the `ez-azfw-ruleman` folder in the table above. No telemetry is collected; the app talks only to Microsoft Entra ID, Azure Resource Manager and the Azure Blob Storage account you choose for snapshots and commit history.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

> **Status:** Windows signing is applied for but not yet active, so Windows builds are currently unsigned. This note will be removed once signing is live.

- **Scope:** only the Windows executables (`.exe`) in [GitHub releases](https://github.com/samsmith-MSFT/ez-azfw-ruleman/releases), built from this repository by the [Release workflow](.github/workflows/release.yml). Nothing built elsewhere is signed.
- **Authors, reviewers and approvers:** [samsmith-MSFT](https://github.com/samsmith-MSFT). Every release needs manual approval before it is signed.
- **Privacy policy:** this program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it. It sends nothing to the maintainers. Its only network connections are to Microsoft Entra ID, Azure Resource Manager and the Azure Blob Storage account you configure, using your own sign-in (see [Where your data is stored](#where-your-data-is-stored)).
- **System changes:** the portable build installs nothing and changes no system settings; delete the file and the data folder above to remove it. The Windows installer adds only a per-user Start menu entry, a desktop shortcut and an uninstall entry, and its uninstaller removes them.

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

| Script              | Description                                                                                                                                   |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm start`         | Run the app in development with hot reload                                                                                                    |
| `npm run lint`      | Lint with oxlint and check formatting with oxfmt                                                                                              |
| `npm run lint:fix`  | Fix lint issues and format                                                                                                                    |
| `npm run typecheck` | Type-check with TypeScript                                                                                                                    |
| `npm test`          | Run unit tests with Vitest                                                                                                                    |
| `npm run verify`    | Lint, type-check, and test (what CI runs)                                                                                                     |
| `npm run package`   | Build the app for the current platform into `out/`                                                                                            |
| `npm run dist`      | Build the Windows installer and portable executable, the Linux AppImage or the macOS zip into `out/release/` (add `-- --arch x64` or `arm64`) |
| `npm run icons`     | Regenerate app icons from `assets/icons/logo.svg`                                                                                             |

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
electron-builder.yml Release targets (Windows installer and portable .exe, Linux AppImage, macOS zip)
vite.*.config.mts    Vite build configuration for main, preload, and renderer
```

## Releasing

1. Add a `## [1.2.3] - YYYY-MM-DD` section to `CHANGELOG.md` and bump the version: `npm version <major|minor|patch> --no-git-tag-version`.
2. Commit, then tag and push: `git tag v1.2.3 && git push origin main v1.2.3`.
3. The [Release workflow](.github/workflows/release.yml) builds a Windows installer and portable executable (x64 and Arm64), plus macOS (arm64 and x64) and Linux (x64) builds, into a draft release. Once **every** build succeeds, it adds `SHA256SUMS.txt`, writes the release notes (a download table plus that version's CHANGELOG section, from [`.github/release-notes.md`](.github/release-notes.md)), and publishes the release as **Latest**.

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

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## Disclaimer

This software is provided "as is", without warranty of any kind, and you use it at your own risk. It changes Azure Firewall policies, which can affect network traffic and security. Review every change before you commit it, test in a non-production environment first, and keep your own backups or snapshots. The authors aren't liable for any outage, data loss, security exposure or other damage that results from using it. See the [LICENSE](LICENSE) for the full terms.

## License

[MIT](LICENSE) © 2026 samsmith-MSFT

This is not an official Microsoft product. Azure and Azure Firewall are trademarks of Microsoft Corporation.
