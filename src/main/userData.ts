// Where the app keeps its data (sign-in, drafts, history, and the key that encrypts saved
// tokens). Imported first in main.ts, because other modules read userData as soon as they load.
// Older azurenetman data is moved over on first launch; retain this path across display-name changes.
import { app } from 'electron';
import fs from 'node:fs';
import path from 'node:path';

const DATA_FOLDER = 'ez-azfw-ruleman';
const LEGACY_FOLDER = 'azurenetman';

/** Saved files that were named after the old app. */
const RENAMED_FILES: [from: string, to: string][] = [
  ['azurenetman-state.json', 'ez-azfw-ruleman-state.json'],
];

function dataFolder(): string {
  const appData = app.getPath('appData');
  const target = path.join(appData, DATA_FOLDER);
  const legacy = path.join(appData, LEGACY_FOLDER);
  if (!fs.existsSync(target) && fs.existsSync(legacy)) {
    try {
      fs.renameSync(legacy, target);
    } catch {
      // Still in use (e.g. an older copy is running): keep using it, and move it next time.
      return legacy;
    }
  }
  return target;
}

const folder = dataFolder();
app.setPath('userData', folder);
for (const [from, to] of RENAMED_FILES) {
  const oldFile = path.join(folder, from);
  const newFile = path.join(folder, to);
  try {
    if (fs.existsSync(oldFile) && !fs.existsSync(newFile))
      fs.renameSync(oldFile, newFile);
  } catch {
    // Leave it; the app starts fresh for that file rather than failing to start.
  }
}
