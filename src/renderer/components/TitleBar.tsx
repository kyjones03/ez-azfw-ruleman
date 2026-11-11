import type { ReactNode } from 'react';
import { MoreHorizontal } from 'lucide-react';
import { Logo } from './Logo';

const isMac = navigator.userAgent.includes('Mac OS');
// Width of the Windows/Linux min/max/close overlay, used if the browser doesn't report it.
const CONTROLS_FALLBACK =
  !isMac && navigator.userAgent.includes('Electron') ? '138px' : '0px';

/**
 * Custom window title bar. The whole bar drags the window; the native window controls are
 * drawn by the OS (titleBarOverlay) on the right, or as traffic lights on macOS.
 */
export function TitleBar({
  bladeOpen,
  onToggleBlade,
  actions,
}: {
  bladeOpen?: boolean;
  onToggleBlade?: () => void;
  /** Right-aligned controls (e.g. the activity bell), kept clear of the window controls. */
  actions?: ReactNode;
}) {
  return (
    <header className="drag relative flex h-9 shrink-0 items-center border-b border-line bg-ink-950">
      {/*
        The title comes first and only spans its own content: Electron computes drag regions from
        element boxes regardless of pointer-events, so a full-width overlay declared after the
        buttons would turn most of them into drag areas.
      */}
      <div className="pointer-events-none absolute left-1/2 flex -translate-x-1/2 items-center gap-2">
        <Logo size={16} />
        <span className="text-sm font-semibold text-fg">EZ AzFW Manager</span>
      </div>
      {onToggleBlade && (
        <button
          type="button"
          onClick={onToggleBlade}
          aria-label={bladeOpen ? 'Collapse navigation' : 'Expand navigation'}
          aria-expanded={bladeOpen}
          title={bladeOpen ? 'Collapse navigation' : 'Expand navigation'}
          className={`no-drag relative flex h-9 w-[52px] items-center justify-center text-fg-muted hover:bg-ink-800 hover:text-fg ${isMac ? 'ml-[76px]' : ''}`}
        >
          <MoreHorizontal size={18} />
        </button>
      )}
      {actions && (
        <div
          className="relative ml-auto flex items-center"
          // Space taken by the OS window controls on the right (0 on macOS and in a browser).
          style={{
            marginRight: `max(${CONTROLS_FALLBACK}, calc(100vw - env(titlebar-area-x, 0px) - env(titlebar-area-width, 100vw)))`,
          }}
        >
          {actions}
        </div>
      )}
    </header>
  );
}
