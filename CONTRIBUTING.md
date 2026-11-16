# Contributing

Thanks for your interest in improving EZ AzFW Manager!

## Reporting issues

- Search [existing issues](https://github.com/samsmith-MSFT/ez-azfw-manager/issues) first.
- Include the app version, your OS, steps to reproduce, and what you expected. Remove subscription IDs, IP addresses, and other sensitive details from screenshots and logs.
- Report security vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Development

1. Install Node.js 22 or later, then run `npm ci`. On Windows, also install the [Microsoft Visual C++ Redistributable (x64)](https://aka.ms/vs/17/release/vc_redist.x64.exe) (`winget install Microsoft.VCRedist.2015+.x64`); a clean machine without it fails during `electron-forge package` with "The specified module could not be found" from `@electron-internal/extract-zip`.
2. Start the app with `npm start`.
3. Before opening a pull request, run `npm run verify` (lint, type-check, and tests) and make sure it passes.

`npm run dist -- --arch x64` (or `arm64`) builds release artifacts for the current OS into `out/release/`. Windows produces an installer and a portable executable; macOS produces a zip and Linux an AppImage. Use GitHub Actions for the full platform matrix.

Set `EZAZFW_DEVTOOLS=1` to open development tools on startup. To use your own public-client Entra app registration, set `EZAZFW_CLIENT_ID` with a `http://localhost` redirect URI; `EZAZFW_TENANT_ID` can preselect a directory. The app deliberately ignores `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` so other tools' service-principal settings do not override it.

## Resetting local data

The app keeps drafts, preferences and sign-in in a per-user folder. To test first-run behavior, quit every running instance (`npm start` and installed builds share this folder), then delete it:

| OS      | Folder                                          |
| ------- | ----------------------------------------------- |
| Linux   | `~/.config/ez-azfw-ruleman`                     |
| macOS   | `~/Library/Application Support/ez-azfw-ruleman` |
| Windows | `%APPDATA%\ez-azfw-ruleman`                     |

Deleting the folder discards saved drafts that were never committed, so copy it first if you need them. The next launch starts at sign-in with no managed firewalls.

To reset only part of it, delete one item while the app is closed:

- `ez-azfw-ruleman-state.json`: drafts, managed firewalls, commit history references, snapshot storage choice, saved session and Event Hub settings for **Firewall logs**.
- `msal-cache.bin`: the encrypted sign-in tokens (**Sign out** in the app does this too).
- `Local Storage/`: interface preferences such as the navigation state, auto-refresh interval and filters.

A local reset does not touch Azure. Shared snapshots and commit history stay in your Blob Storage account; choose it again on the **Snapshots** page afterwards.

## Pull requests

- Keep changes focused; open an issue first for larger changes.
- Add or update tests in `src/**/*.test.ts` for logic changes, particularly in `src/shared/`.
- Format code with `npm run lint:fix`.
- Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

## Releasing

1. Add a dated version section to [CHANGELOG.md](CHANGELOG.md) and run `npm version <version> --no-git-tag-version`.
2. Run `npm run verify` and validate the affected release builds.
3. Commit, then tag and push: `git tag v<version>` and `git push origin main v<version>`.

The tag must match `package.json`. The [Release workflow](.github/workflows/release.yml) builds every supported platform into a draft, adds checksums and changelog-based notes, and publishes as Latest only after all builds succeed. Failed builds leave the release in draft; fix the failure and rerun the jobs or dispatch the workflow with the existing tag.

### Optional signing

Signing is opt-in through repository secrets:

| Platform           | Settings                                                                                 |
| ------------------ | ---------------------------------------------------------------------------------------- |
| Windows            | `WINDOWS_CERTIFICATE` (base64 PFX), `WINDOWS_CERTIFICATE_PASSWORD`                       |
| macOS              | `APPLE_CERTIFICATE` (base64 P12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY` |
| macOS notarization | `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`                               |

Local builds use `WINDOWS_CERTIFICATE_FILE`/`WINDOWS_CERTIFICATE_PASSWORD` and the corresponding Apple environment variables. Never commit signing material or credentials. Public signing and privacy commitments are in the README's [Code signing policy](README.md#code-signing-policy).

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
