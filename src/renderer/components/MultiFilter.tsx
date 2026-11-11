import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from 'react';
import { createPortal } from 'react-dom';
import { Check, ChevronDown, Search, X } from 'lucide-react';

export interface FilterOption {
  value: string;
  label?: string;
  /** Shown faint after the label, e.g. a count. */
  hint?: string;
}

/**
 * A filter button that opens a searchable checklist (Azure portal style). Nothing selected means
 * "all"; the menu stays open while ticking options.
 */
export function MultiFilter({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: FilterOption[];
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [position, setPosition] = useState<CSSProperties>();
  const button = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const chosen = useMemo(() => new Set(selected), [selected]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q
      ? options.filter((o) =>
          `${o.label ?? o.value} ${o.value}`.toLowerCase().includes(q),
        )
      : options;
  }, [options, query]);

  const place = useCallback(() => {
    const a = button.current?.getBoundingClientRect();
    if (!a) return;
    setPosition({
      position: 'fixed',
      top: a.bottom + 4,
      left: Math.min(a.left, window.innerWidth - 296),
      minWidth: Math.max(a.width, 280),
    });
  }, []);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    search.current?.focus();
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!button.current?.contains(t) && !panel.current?.contains(t))
        setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      document.removeEventListener('mousedown', onDown);
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
  }, [open, place]);

  const toggle = (value: string) =>
    onChange(
      chosen.has(value)
        ? selected.filter((v) => v !== value)
        : [...selected, value],
    );

  const labelOf = (v: string) => options.find((o) => o.value === v)?.label ?? v;
  const summary = !selected.length
    ? 'All'
    : selected.length === 1
      ? labelOf(selected[0])
      : `${selected.length} selected`;

  return (
    <>
      <button
        ref={button}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`${label} filter`}
        title={
          selected.length
            ? `${label}: ${selected.map(labelOf).join(', ')}`
            : undefined
        }
        onClick={() => {
          setQuery('');
          setOpen((o) => !o);
        }}
        className={`flex h-8 max-w-[15rem] items-center gap-1.5 rounded border px-3 text-sm ${
          selected.length
            ? 'border-azure/60 bg-azure/15 text-fg'
            : 'border-line text-fg-muted hover:border-fg-faint hover:text-fg'
        }`}
      >
        <span className="shrink-0">{label}:</span>
        <span
          className={`truncate ${selected.length ? 'font-medium' : 'text-fg-faint'}`}
        >
          {summary}
        </span>
        <ChevronDown size={13} className="shrink-0" />
      </button>
      {open &&
        createPortal(
          <div
            ref={panel}
            style={position ?? { position: 'fixed', visibility: 'hidden' }}
            className="z-50 flex w-72 flex-col border border-line bg-ink-850 shadow-[0_16px_40px_rgba(4,10,20,0.55)]"
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                setOpen(false);
                button.current?.focus();
              }
            }}
          >
            <div className="relative border-b border-line p-2">
              <Search
                size={14}
                className="absolute left-4 top-[17px] text-fg-faint"
              />
              <input
                ref={search}
                className="input pl-8"
                aria-label={`Search ${label.toLowerCase()}`}
                placeholder={`Search ${label.toLowerCase()}…`}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  // Enter ticks the only match, a quick way to filter by typing.
                  if (e.key === 'Enter' && visible.length === 1) {
                    e.preventDefault();
                    toggle(visible[0].value);
                  }
                }}
              />
            </div>
            <div className="flex items-center justify-between border-b border-line px-3 py-1.5 text-xs">
              <button
                type="button"
                className="text-azure hover:underline disabled:text-fg-faint disabled:no-underline"
                disabled={!visible.length}
                onClick={() =>
                  onChange([
                    ...new Set([...selected, ...visible.map((o) => o.value)]),
                  ])
                }
              >
                Select {query ? 'matches' : 'all'}
              </button>
              <button
                type="button"
                className="inline-flex items-center gap-1 text-fg-muted hover:text-fg disabled:text-fg-faint"
                disabled={!selected.length}
                onClick={() => onChange([])}
              >
                <X size={12} /> Clear
              </button>
            </div>
            <ul
              role="listbox"
              aria-multiselectable
              aria-label={label}
              className="max-h-72 overflow-y-auto py-1"
            >
              {visible.map((o) => {
                const on = chosen.has(o.value);
                return (
                  <li key={o.value}>
                    <button
                      type="button"
                      role="option"
                      aria-selected={on}
                      onClick={() => toggle(o.value)}
                      className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-ink-800"
                    >
                      <span
                        className={`flex h-4 w-4 shrink-0 items-center justify-center border ${on ? 'border-azure bg-azure text-ink-950' : 'border-line'}`}
                      >
                        {on && <Check size={12} strokeWidth={3} />}
                      </span>
                      <span
                        className="min-w-0 flex-1 truncate"
                        title={o.label ?? o.value}
                      >
                        {o.label ?? o.value}
                      </span>
                      {o.hint && (
                        <span className="shrink-0 text-xs text-fg-faint">
                          {o.hint}
                        </span>
                      )}
                    </button>
                  </li>
                );
              })}
              {!visible.length && (
                <li className="px-3 py-2 text-sm text-fg-faint">
                  {options.length ? 'No matches.' : 'Nothing to filter by.'}
                </li>
              )}
            </ul>
          </div>,
          document.body,
        )}
    </>
  );
}
