// Guards the bundled Event Hubs client. Bundling CommonJS drops "use strict", which breaks
// rhea-promise (see vite.rhea.plugin.mts); unit tests with a fake client cannot notice that, so
// this builds the real SDK the way the main process does and runs it.
import { mkdirSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { builtinModules } from 'node:module';
import path from 'node:path';
import { build } from 'vite';
import { describe, expect, it } from 'vitest';
import { isStrictPackageFile, rheaStrict } from '../../vite.rhea.plugin';

const root = path.resolve(__dirname, '../..');

describe('bundled Event Hubs client', () => {
  it('still ships rhea modules that depend on strict mode', () => {
    // If this fails after a dependency update, check whether rhea / rhea-promise changed (the
    // plugin may no longer be needed) before touching vite.rhea.plugin.mts.
    for (const file of [
      'node_modules/rhea/lib/container.js',
      'node_modules/rhea-promise/dist/lib/connection.js',
    ]) {
      const source = readFileSync(path.join(root, file), 'utf8');
      expect(source).toMatch(/['"]use strict['"]/);
      expect(isStrictPackageFile(path.join(root, file))).toBe(true);
    }
    expect(
      readFileSync(
        path.join(root, 'node_modules/rhea-promise/dist/lib/connection.js'),
        'utf8',
      ),
    ).toContain('(0, rhea_1.create_connection)(');
  });

  it('gets to the network layer instead of failing inside rhea', async () => {
    // Inside the repo (git-ignored `out/`) so the entry can resolve node_modules.
    mkdirSync(path.join(root, 'out'), { recursive: true });
    const dir = mkdtempSync(path.join(root, 'out', 'test-eh-'));
    try {
      const entry = path.join(dir, 'entry.ts');
      // The credential never has to be asked: the namespace does not resolve.
      writeFileSync(
        entry,
        `import { EventHubConsumerClient } from '@azure/event-hubs';
         const credential = { getToken: async () => ({ token: 'x.y.z', expiresOnTimestamp: Date.now() + 3.6e6 }) };
         const client = new EventHubConsumerClient('$Default', 'does-not-exist-zz-12345.servicebus.windows.net', 'hub', credential as never, { retryOptions: { maxRetries: 0 } });
         client.getPartitionIds({ abortSignal: AbortSignal.timeout(8000) })
           .then(() => console.log('RESULT ok'), (e) => console.log('RESULT ' + (e?.name ?? '') + ' ' + (e?.message ?? e)))
           .finally(() => client.close().finally(() => process.exit(0)));`,
      );
      await build({
        root,
        configFile: false,
        logLevel: 'silent',
        plugins: [rheaStrict()],
        build: {
          outDir: path.join(dir, 'out'),
          minify: false,
          ssr: true,
          lib: { entry, formats: ['cjs'], fileName: () => 'entry.cjs' },
          rollupOptions: {
            external: [
              'electron',
              ...builtinModules,
              ...builtinModules.map((m) => `node:${m}`),
            ],
          },
        },
        ssr: { noExternal: true },
        resolve: { conditions: ['node'] },
      });
      const out = execFileSync(
        process.execPath,
        [
          path.join(
            dir,
            'out',
            readdirSync(path.join(dir, 'out')).find((f) => /\.c?js$/.test(f)) ??
              'missing.js',
          ),
        ],
        {
          encoding: 'utf8',
          timeout: 20_000,
        },
      );
      expect(out).toMatch(/RESULT /);
      expect(out).not.toMatch(/get_option|is not a function/);
      // Offline machines report EAI_AGAIN, online ones ENOTFOUND; both come from the socket layer.
      expect(out).toMatch(
        /ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|did not respond/i,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 40_000);
});
