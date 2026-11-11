// EZ AzFW Manager — main process entry point.
// Must be first: pins the data folder before other modules read it.
import './main/userData';
import { app, BrowserWindow, dialog, Menu, session } from 'electron';
import path from 'node:path';
import { registerIpc } from './main/ipc';
import { candidate } from './main/candidate';
import {
  APP_ORIGIN,
  isAppUrl,
  registerAppScheme,
  serveAppFiles,
} from './main/appProtocol';

let mainWindow: BrowserWindow | undefined;

const TITLE_BAR_HEIGHT = 36;

// Packaged builds ship the icons as extra resources; in development they live in the repo.
function appIconPath(): string {
  const file = process.platform === 'win32' ? 'icon.ico' : 'icon.png';
  return app.isPackaged
    ? path.join(process.resourcesPath, file)
    : path.join(app.getAppPath(), 'assets', 'icons', file);
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    icon: appIconPath(),
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 680,
    show: false,
    backgroundColor: '#0F1B2D',
    title: 'EZ AzFW Manager',
    // Custom title bar: the renderer draws the bar; the OS keeps the native window controls.
    titleBarStyle: 'hidden',
    titleBarOverlay:
      process.platform === 'darwin'
        ? undefined
        : {
            color: '#0B1524',
            symbolColor: '#93A4BD',
            height: TITLE_BAR_HEIGHT,
          },
    trafficLightPosition: { x: 14, y: 11 },
    roundedCorners: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Developer tools only in development builds.
      devTools: !app.isPackaged,
    },
  });

  mainWindow.once('ready-to-show', () => mainWindow?.show());

  // The renderer never navigates or opens windows; block anything that tries.
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isAppUrl(url)) event.preventDefault();
  });

  mainWindow.on('close', (event) => {
    if (!candidate.unsaved || !mainWindow) return;
    const choice = dialog.showMessageBoxSync(mainWindow, {
      type: 'warning',
      buttons: ['Save', "Don't save", 'Cancel'],
      defaultId: 0,
      cancelId: 2,
      title: 'Unsaved changes',
      message: 'You have unsaved candidate changes.',
      detail:
        'Save them to keep them for a later commit. Nothing has been sent to Azure.',
    });
    if (choice === 2) {
      event.preventDefault();
    } else if (choice === 0) {
      try {
        candidate.save();
      } catch (err) {
        event.preventDefault();
        dialog.showErrorBox(
          "Couldn't save your changes",
          `${(err as Error).message}\n\nThe window stays open so nothing is lost.`,
        );
      }
    }
  });
  mainWindow.on('closed', () => {
    mainWindow = undefined;
  });

  const url = MAIN_WINDOW_VITE_DEV_SERVER_URL || `${APP_ORIGIN}/index.html`;
  mainWindow.loadURL(url).catch((err: Error) => {
    console.error(`[window] Couldn't load ${url}:`, err.message);
  });
  // Opt in with EZAZFW_DEVTOOLS=1; Ctrl+Shift+I still toggles them.
  if (MAIN_WINDOW_VITE_DEV_SERVER_URL && process.env.EZAZFW_DEVTOOLS)
    mainWindow.webContents.openDevTools({ mode: 'detach' });
}

function onReady(): void {
  // Must match the installer's appId so the taskbar groups and pins the app with its shortcuts.
  if (process.platform === 'win32')
    app.setAppUserModelId('com.samsmithmsft.ezazfwruleman');
  // In development macOS shows the Electron dock icon unless told otherwise.
  if (process.platform === 'darwin' && !app.isPackaged)
    app.dock?.setIcon(appIconPath());
  // The app needs no browser permissions (camera, notifications, etc.), except writing text to
  // the clipboard for its "Copy" actions — and only from the app's own pages.
  session.defaultSession.setPermissionRequestHandler(
    (_wc, permission, callback, details) =>
      callback(
        permission === 'clipboard-sanitized-write' &&
          isAppUrl(details.requestingUrl),
      ),
  );
  if (!MAIN_WINDOW_VITE_DEV_SERVER_URL)
    serveAppFiles(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}`));
  // Packaged builds get a minimal menu: editing shortcuts (and the standard macOS app menu), no
  // View menu with reload or developer tools.
  if (app.isPackaged)
    Menu.setApplicationMenu(
      Menu.buildFromTemplate([
        ...(process.platform === 'darwin'
          ? [{ role: 'appMenu' as const }]
          : []),
        { role: 'editMenu' },
        ...(process.platform === 'darwin'
          ? [{ role: 'windowMenu' as const }]
          : []),
      ]),
    );
  registerIpc(() => mainWindow?.webContents);
  createWindow();

  // On macOS the app stays running without windows; clicking the dock icon opens one again.
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
}

function start(): void {
  // The packaged UI is served from app://bundle; the scheme must be registered before ready.
  registerAppScheme();

  // A second launch focuses this window instead of starting another copy.
  app.on('second-instance', () => {
    if (!mainWindow) {
      if (app.isReady()) createWindow();
      return;
    }
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });

  // Quit when all windows are closed, except on macOS.
  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });

  app
    .whenReady()
    .then(onReady)
    .catch((err: Error) => {
      dialog.showErrorBox("EZ AzFW Manager couldn't start", err.message);
      app.quit();
    });
}

if (!app.requestSingleInstanceLock()) {
  // Another copy is already running and owns the data folder (drafts, history, sign-in).
  app.quit();
} else {
  start();
}
