# Contributing

Thanks for your interest in improving EZ AzFW Manager!

## Reporting issues

- Search [existing issues](https://github.com/samsmith-MSFT/ez-azfw-manager/issues) first.
- Include the app version, your OS, steps to reproduce, and what you expected. Remove subscription IDs, IP addresses, and other sensitive details from screenshots and logs.
- Report security vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Development

1. Install Node.js 22 or later, then run `npm ci`.
2. Start the app with `npm start`.
3. Before opening a pull request, run `npm run verify` (lint, type-check, and tests) and make sure it passes.

## Pull requests

- Keep changes focused; open an issue first for larger changes.
- Add or update tests in `src/**/*.test.ts` for logic changes, particularly in `src/shared/`.
- Format code with `npm run lint:fix`.
- Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
