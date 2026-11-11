import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { X } from 'lucide-react';

/** Open modals, innermost last: Escape closes only the innermost one. */
const openModals: object[] = [];

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function useGuardedClose(dirty: boolean, onClose: () => void) {
  const [asking, setAsking] = useState(false);
  return {
    request: () => (dirty ? setAsking(true) : onClose()),
    dialog: asking ? (
      <ConfirmModal
        title="Discard your edits?"
        message="What you typed in this dialog hasn't been added to the draft yet."
        confirmLabel="Discard"
        onCancel={() => setAsking(false)}
        onConfirm={onClose}
      />
    ) : null,
  };
}

export function Modal({
  title,
  subtitle,
  onClose,
  children,
  footer,
  widthClass = 'max-w-2xl',
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  widthClass?: string;
}) {
  const dialog = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  // Read while rendering: by the time effects run, an autoFocus child already has focus.
  const [opener] = useState(() =>
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null,
  );

  useEffect(() => {
    const token = {};
    openModals.push(token);
    // Children with autoFocus have already taken focus; otherwise focus the dialog itself.
    if (!dialog.current?.contains(document.activeElement))
      dialog.current?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (
        e.key === 'Escape' &&
        !e.defaultPrevented &&
        openModals.at(-1) === token
      )
        onCloseRef.current();
    };
    window.addEventListener('keydown', onKey);
    const node = dialog.current;
    return () => {
      window.removeEventListener('keydown', onKey);
      openModals.splice(openModals.indexOf(token), 1);
      // Give focus back to what opened the dialog once it's really gone (not on a StrictMode
      // re-run, where the DOM stays).
      queueMicrotask(() => {
        if (!node?.isConnected && opener?.isConnected) opener.focus();
      });
    };
  }, [opener]);

  // Keeps Tab within the dialog. Popups portaled out of it (menus, pickers) manage their own focus.
  const trapTab = (e: React.KeyboardEvent) => {
    if (e.key !== 'Tab' || !dialog.current) return;
    const items = [
      ...dialog.current.querySelectorAll<HTMLElement>(FOCUSABLE),
    ].filter((el) => !el.hidden && el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === dialog.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-ink-950/75 p-6"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onKeyDown={trapTab}
        className={`flex max-h-full w-full ${widthClass} flex-col border border-line bg-ink-850 shadow-[0_24px_60px_rgba(4,10,20,0.6)] focus:outline-none`}
      >
        <header className="flex items-start gap-3 border-b border-line px-5 py-3.5">
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="truncate text-lg font-semibold text-fg">
              {title}
            </h2>
            {subtitle && (
              <p className="mt-0.5 truncate text-sm text-fg-muted">
                {subtitle}
              </p>
            )}
          </div>
          <button
            type="button"
            className="btn-ghost w-8 justify-center px-0"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {children}
        </div>
        {footer && (
          <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}

export function ConfirmModal({
  title,
  message,
  confirmLabel = 'Delete',
  onConfirm,
  onCancel,
}: {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      widthClass="max-w-md"
      footer={
        <>
          <button className="btn-ghost" onClick={onCancel}>
            Cancel
          </button>
          <button className="btn-danger" onClick={onConfirm} autoFocus>
            {confirmLabel}
          </button>
        </>
      }
    >
      <div className="text-sm text-fg-muted">{message}</div>
    </Modal>
  );
}
