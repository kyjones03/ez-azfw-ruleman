import type { Plugin } from 'vite';

/**
 * Keeps rhea and rhea-promise (the AMQP layer under @azure/event-hubs) strict.
 *
 * Their CommonJS modules start with "use strict" and rely on it: rhea-promise calls
 * `(0, rhea_1.create_connection)(...)`, the container method with no receiver, which in strict
 * code gets `this === undefined` (no container) but in sloppy code gets the global object. The
 * bundler drops "use strict" from bundled CommonJS modules, so the bundle failed on connect with
 * "this.container.get_option is not a function". Wrapping just these two packages in a strict
 * function restores the semantics they were written for, without changing how any other
 * dependency of the app runs.
 *
 * `src/main/eventHubBundle.test.ts` builds the real SDK with this plugin and runs it.
 */
const STRICT_PACKAGES = ['/node_modules/rhea/', '/node_modules/rhea-promise/'];

export function isStrictPackageFile(id: string): boolean {
  const file = id.split('?')[0].replace(/\\/g, '/');
  return file.endsWith('.js') && STRICT_PACKAGES.some((p) => file.includes(p));
}

export function rheaStrict(): Plugin {
  return {
    name: 'rhea-strict',
    enforce: 'pre',
    transform(code, id) {
      if (!isStrictPackageFile(id)) return null;
      return {
        code: `(function () {\n"use strict";\n${code}\n}).call(exports);`,
        map: null,
      };
    },
  };
}
