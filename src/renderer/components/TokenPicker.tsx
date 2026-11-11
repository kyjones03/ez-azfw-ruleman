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
import { Check, ChevronDown, Loader2, Search, X } from 'lucide-react';
import { parseList } from '../../shared/rules';

export interface PickerOption {
  value: string;
  label: string;
  hint?: string;
  /** Tooltip, e.g. an IP Group's members. */
  title?: string;
}

const MAX_SHOWN = 100;

/**
 * Multi-value picker over a comma-separated value. The field shows the selected values as chips;
 * clicking it opens a list with a search box at the top. Items toggle on click and the list
 * stays open for picking several. With `allowCustom`, values not in the list can be typed in
 * the search box and added with Enter (used when the list couldn't be loaded from Azure).
 */
export function TokenPicker({
  value,
  onChange,
  options,
  ariaLabel,
  placeholder,
  loading,
  allowCustom,
  disabled = false,
  invalid,
  emptyText = 'No matches',
}: {
  value: string;
  onChange: (value: string) => void;
  options: PickerOption[];
  ariaLabel: string;
  placeholder?: string;
  loading?: boolean;
  allowCustom?: boolean;
  disabled?: boolean;
  invalid?: boolean;
  emptyText?: string;
}) {
  const tokens = parseList(value);
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);
  const [active, setActive] = useState(0);
  const [position, setPosition] = useState<CSSProperties>();
  const box = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);

  const byValue = useMemo(
    () => new Map(options.map((o) => [o.value.toLowerCase(), o])),
    [options],
  );
  const selected = new Set(tokens.map((t) => t.toLowerCase()));
  const q = query.trim().toLowerCase();
  const matches = useMemo(() => {
    const isSelected = (o: PickerOption) => selected.has(o.value.toLowerCase());
    return (
      options
        .filter(
          (o) =>
            !q ||
            o.label.toLowerCase().includes(q) ||
            (o.hint ?? '').toLowerCase().includes(q),
        )
        // Selected first, then names starting with the search, then the rest.
        .sort(
          (a, b) =>
            Number(isSelected(b)) - Number(isSelected(a)) ||
            Number(!a.label.toLowerCase().startsWith(q)) -
              Number(!b.label.toLowerCase().startsWith(q)),
        )
    );
    // selected is derived from value.
  }, [options, q, value]);
  const shown = matches.slice(0, MAX_SHOWN);

  const setTokens = (next: string[]) => onChange(next.join(', '));
  const toggle = (v: string) => {
    const lower = v.toLowerCase();
    setTokens(
      selected.has(lower)
        ? tokens.filter((t) => t.toLowerCase() !== lower)
        : [...tokens, v],
    );
  };
  const remove = (t: string) => setTokens(tokens.filter((x) => x !== t));
  const addCustom = () => {
    const extra = parseList(query).filter(
      (t) => !selected.has(t.toLowerCase()),
    );
    if (extra.length) setTokens([...tokens, ...extra]);
    setQuery('');
  };

  const close = (refocus = false) => {
    setOpen(false);
    setQuery('');
    setPosition(undefined);
    if (refocus) box.current?.focus();
  };

  const place = useCallback(() => {
    const r = box.current?.getBoundingClientRect();
    if (!r) return;
    const below = window.innerHeight - r.bottom;
    const style: CSSProperties = {
      position: 'fixed',
      left: r.left,
      width: Math.max(r.width, 300),
    };
    if (below < 300 && r.top > below)
      style.bottom = window.innerHeight - r.top + 2;
    else style.top = r.bottom + 2;
    setPosition(style);
  }, []);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  // Focus the search once the list has actually rendered (it needs a position first).
  const panelShown = open && !!position;
  useLayoutEffect(() => {
    if (panelShown) search.current?.focus();
  }, [panelShown]);

  // Chips can change the field's height, so keep the list attached to it.
  useLayoutEffect(() => {
    if (open) place();
  }, [value, open, place]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!box.current?.contains(t) && !panel.current?.contains(t)) close();
    };
    document.addEventListener('mousedown', onDown);
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => {
      document.removeEventListener('mousedown', onDown);
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
    };
  }, [open, place]);

  useEffect(() => setActive(0), [q]);

  useEffect(() => {
    list.current
      ?.querySelector(`[data-index="${active}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const label = (t: string) =>
    byValue.get(t.toLowerCase())?.label ??
    (t.startsWith('/') ? t.split('/').pop()! : t);

  const summary = tokens.length
    ? tokens.map(label).join(', ')
    : (placeholder ?? '');

  return (
    <>
      <div
        ref={box}
        role="combobox"
        tabIndex={disabled ? -1 : 0}
        aria-label={ariaLabel}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-invalid={invalid}
        aria-disabled={disabled}
        title={summary}
        className={`input relative flex min-h-8 flex-wrap items-center gap-1 py-[3px] pl-1 pr-6 ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} ${invalid ? 'border-deny' : ''}`}
        onClick={() => {
          if (disabled) return;
          if (open) close();
          else setOpen(true);
        }}
        onKeyDown={(e) => {
          if (disabled) return;
          if (
            !open &&
            (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown')
          ) {
            e.preventDefault();
            setOpen(true);
          } else if (e.key === 'Backspace' && tokens.length) {
            remove(tokens[tokens.length - 1]);
          }
        }}
      >
        {tokens.map((t) => {
          const o = byValue.get(t.toLowerCase());
          return (
            <span
              key={t}
              title={o?.title ?? t}
              className={`inline-flex max-w-full items-center gap-0.5 rounded border px-1.5 font-mono text-[11px] leading-5 ${o || !options.length ? 'border-azure/40 bg-azure/10 text-fg' : 'border-deny/50 bg-deny/10 text-deny'}`}
            >
              <span className="truncate">{label(t)}</span>
              <button
                type="button"
                disabled={disabled}
                className="text-fg-faint hover:text-fg"
                aria-label={`Remove ${label(t)}`}
                onClick={(e) => {
                  e.stopPropagation();
                  remove(t);
                }}
              >
                <X size={11} />
              </button>
            </span>
          );
        })}
        {!tokens.length && (
          <span className="truncate px-1 font-mono text-xs text-fg-faint">
            {placeholder}
          </span>
        )}
        <ChevronDown
          size={13}
          className={`absolute right-1.5 top-[9px] text-fg-faint transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </div>
      {open &&
        position &&
        createPortal(
          <div
            ref={panel}
            style={position}
            className="z-[60] flex flex-col border border-line bg-ink-850 shadow-[0_16px_40px_rgba(4,10,20,0.55)]"
          >
            <div className="relative border-b border-line p-2">
              <Search
                size={13}
                className="absolute left-4 top-[17px] text-fg-faint"
              />
              <input
                ref={search}
                className="input h-8 pl-7 text-xs"
                aria-label={`Search ${ariaLabel.toLowerCase()}`}
                placeholder={
                  allowCustom
                    ? 'Search, or type a value and press Enter'
                    : 'Search…'
                }
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    setActive((i) => Math.min(i + 1, shown.length - 1));
                  } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    setActive((i) => Math.max(i - 1, 0));
                  } else if (e.key === 'Enter') {
                    e.preventDefault();
                    // Enter only adds; removing is done by clicking a ticked item or a chip's ×,
                    // so an Enter with an empty search can't drop a value by accident.
                    const hit = q ? shown[active] : undefined;
                    if (hit && !selected.has(hit.value.toLowerCase())) {
                      toggle(hit.value);
                      setQuery('');
                    } else if (allowCustom && q) addCustom();
                  } else if (e.key === 'Escape') {
                    // Close the list, not the dialog around it.
                    e.preventDefault();
                    e.stopPropagation();
                    close(true);
                  } else if (e.key === 'Tab') {
                    close();
                  }
                }}
              />
            </div>
            <ul
              ref={list}
              role="listbox"
              aria-label={`${ariaLabel} options`}
              aria-multiselectable
              className="max-h-64 overflow-y-auto py-1"
            >
              {loading && !options.length ? (
                <li className="flex items-center gap-2 px-3 py-1.5 text-xs text-fg-faint">
                  <Loader2 size={12} className="animate-spin" /> Loading from
                  Azure…
                </li>
              ) : shown.length ? (
                shown.map((o, i) => {
                  const on = selected.has(o.value.toLowerCase());
                  return (
                    <li
                      key={o.value}
                      data-index={i}
                      role="option"
                      aria-selected={on}
                      title={o.title ?? o.label}
                      onMouseEnter={() => setActive(i)}
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => toggle(o.value)}
                      className={`flex cursor-pointer items-center gap-2 border-l-2 px-3 py-1 text-sm ${i === active ? 'border-azure bg-ink-800' : 'border-transparent'}`}
                    >
                      <span className="flex w-3.5 shrink-0 justify-center text-azure">
                        {on && <Check size={13} />}
                      </span>
                      <span className="truncate font-mono text-xs text-fg">
                        {o.label}
                      </span>
                      {o.hint && (
                        <span className="ml-auto shrink-0 truncate text-[11px] text-fg-faint">
                          {o.hint}
                        </span>
                      )}
                    </li>
                  );
                })
              ) : (
                <li className="px-3 py-1.5 text-xs text-fg-faint">
                  {allowCustom && q
                    ? `Press Enter to add "${query.trim()}"`
                    : emptyText}
                </li>
              )}
            </ul>
            <div className="flex items-center justify-between border-t border-line px-3 py-1 text-[11px] text-fg-faint">
              <span>
                {tokens.length} selected
                {matches.length > MAX_SHOWN &&
                  ` · ${matches.length - MAX_SHOWN} more, keep typing to narrow down`}
              </span>
              <button
                type="button"
                className="text-azure hover:underline"
                onClick={() => close(true)}
              >
                Done
              </button>
            </div>
          </div>,
          document.body,
        )}
    </>
  );
}
