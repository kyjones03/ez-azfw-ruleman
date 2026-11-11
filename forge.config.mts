import type { ForgeConfig } from '@electron-forge/shared-types';
import { VitePlugin } from '@electron-forge/plugin-vite';
import { FusesPlugin } from '@electron-forge/plugin-fuses';
import { FuseV1Options, FuseVersion } from '@electron/fuses';

const env = (name: string): string | undefined =>
  process.env[name]?.trim() || undefined;

// Code signing is opt-in: every value comes from the environment, and without it the build is
// unsigned. macOS signs with a keychain identity (APPLE_SIGNING_IDENTITY) and notarizes when the
// Apple ID credentials are also present. Windows signs with a .pfx file.
const macIdentity = env('APPLE_SIGNING_IDENTITY');
const appleId = env('APPLE_ID');
const applePassword =
  env('APPLE_APP_SPECIFIC_PASSWORD') ?? env('APPLE_PASSWORD');
const appleTeamId = env('APPLE_TEAM_ID');
const notarize = Boolean(
  macIdentity && appleId && applePassword && appleTeamId,
);

const winCertFile = env('WINDOWS_CERTIFICATE_FILE');
const windowsSign = winCertFile
  ? {
      certificateFile: winCertFile,
      certificatePassword: env('WINDOWS_CERTIFICATE_PASSWORD'),
    }
  : undefined;

const config: ForgeConfig = {
  packagerConfig: {
    asar: true,
    executableName: 'ez-azfw-manager',
    // Keep the original application ID so existing installations remain compatible.
    appBundleId: 'com.samsmithmsft.ezazfwruleman',
    appCategoryType: 'public.app-category.developer-tools',
    appCopyright: 'Copyright (c) 2026 samsmith-MSFT',
    // Forge picks icon.ico / icon.icns by platform.
    icon: './assets/icons/icon',
    // The window icon is loaded at runtime from the resources folder.
    extraResource: ['./assets/icons/icon.ico', './assets/icons/icon.png'],
    win32metadata: {
      CompanyName: 'samsmith-MSFT',
      FileDescription: 'EZ AzFW Manager',
      ProductName: 'EZ AzFW Manager',
      InternalName: 'ez-azfw-manager',
      OriginalFilename: 'ez-azfw-manager.exe',
    },
    ...(macIdentity ? { osxSign: { identity: macIdentity } } : {}),
    ...(notarize
      ? {
          osxNotarize: {
            appleId: appleId!,
            appleIdPassword: applePassword!,
            teamId: appleTeamId!,
          },
        }
      : {}),
    ...(windowsSign ? { windowsSign } : {}),
  },
  rebuildConfig: {},
  // Forge only builds the app (`electron-forge package`); scripts/dist.mjs turns it into
  // portable executables with electron-builder.
  makers: [],
  plugins: [
    new VitePlugin({
      // `build` can specify multiple entry builds, which can be Main process, Preload scripts, Worker process, etc.
      // If you are familiar with Vite configuration, it will look really familiar.
      build: [
        {
          // `entry` is just an alias for `build.lib.entry` in the corresponding file of `config`.
          entry: 'src/main.ts',
          config: 'vite.main.config.mts',
          target: 'main',
        },
        {
          entry: 'src/preload.ts',
          config: 'vite.preload.config.mts',
          target: 'preload',
        },
      ],
      renderer: [
        {
          name: 'main_window',
          config: 'vite.renderer.config.mts',
        },
      ],
    }),
    // Fuses are used to enable/disable various Electron functionality
    // at package time, before code signing the application
    new FusesPlugin({
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
      // The UI is served from app://, so file:// needs no extra privileges.
      [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
    }),
  ],
};

export default config;
