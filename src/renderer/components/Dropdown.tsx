import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { MoreHorizontal, ChevronDown, Check, Search } from 'lucide-react';

export interface MenuItem {
  /** Stable identity when labels can repeat (defaults to the label). */
  id?: string;
  label: string;
  icon?: ReactNode;
  onSelect?: () => void;
  danger?: boolean;
  disabled?: boolean;
  checked?: boolean;
  hint?: string;
  divider?: boolean;
}

interface DropdownProps {
  trigger: (open: boolean) => ReactNode;
  items: MenuItem[];
  align?: 'left' | 'right';
  header?: ReactNode;
  widthClass?: string;
  label?: string;
  disabled?: boolean;
  'aria-invalid'?: boolean;
  triggerClassName?: string;
  /** Adds a search box and a fixed-height scrolling list (for long option lists). */
  searchable?: boolean;
  searchPlaceholder?: string;
}

/**
 * Accessible dropdown menu: click/Enter to open, arrow keys to move, Esc or outside click to close.
 * Long lists can be searchable, with a fixed-height scrolling list.
 */
export function Dropdown({
  trigger,
  items,
  align = 'left',
  header,
  widthClass = 'w-56',
  label,
  disabled,
  'aria-invalid': invalid,
  triggerClassName = '',
  searchable = false,
  searchPlaceholder = 'Search…',
}: DropdownProps) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [query, setQuery] = useState('');
  const [position, setPosition] = useState<CSSProperties>();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const itemRefs = useRef(new Map<number, HTMLButtonElement>());
  // Decided once per opening, so the menu doesn't jump while a search shrinks the list.
  const flipUp = useRef(false);
  const fullWidth = widthClass.includes('w-full');

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!searchable || !q) return items;
    return items.filter(
      (it) =>
        !it.divider && `${it.label} ${it.hint ?? ''}`.toLowerCase().includes(q),
    );
  }, [items, query, searchable]);

  const selectable = visible
    .map((it, i) => (!it.divider && !it.disabled ? i : -1))
    .filter((i) => i >= 0);

  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (!root.current?.contains(target) && !menu.current?.contains(target))
        setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  /**
   * The menu is portaled to <body> with fixed positioning, so it never changes the size or
   * scrollbars of whatever contains the trigger (e.g. a dialog's scrolling body).
   */
  const place = useCallback(() => {
    const anchor = button.current?.getBoundingClientRect();
    if (!anchor) return;
    const style: CSSProperties = { position: 'fixed' };
    if (fullWidth) style.width = anchor.width;
    else style.minWidth = anchor.width;
    if (align === 'right') style.right = window.innerWidth - anchor.right;
    else style.left = anchor.left;
    if (flipUp.current) style.bottom = window.innerHeight - anchor.top + 4;
    else style.top = anchor.bottom + 4;
    setPosition(style);
  }, [align, fullWidth]);

  useLayoutEffect(() => {
    if (!open) return;
    flipUp.current = false;
    place();
  }, [open, place]);

  // Keep the menu attached to its trigger when anything scrolls or the window resizes.
  useEffect(() => {
    if (!open) return;
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => {
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
    };
  }, [open, place]);

  useLayoutEffect(() => {
    if (!open || !position || !menu.current) return;
    const rect = menu.current.getBoundingClientRect();
    const anchor = button.current?.getBoundingClientRect();
    // Flip up only when it doesn't fit below but does fit above.
    if (
      !flipUp.current &&
      anchor &&
      rect.bottom > window.innerHeight - 8 &&
      anchor.top - rect.height > 8
    ) {
      flipUp.current = true;
      place();
    }
    // Only once the menu has its first position.
  }, [position === undefined]);

  useLayoutEffect(() => {
    if (!open || !position || !menu.current) return;
    if (searchable) {
      search.current?.focus();
      // Start with the current selection in view.
      const checked = visible.findIndex((it) => it.checked);
      if (checked >= 0) {
        setActive(checked);
        itemRefs.current.get(checked)?.scrollIntoView({ block: 'center' });
      }
    } else {
      menu.current.focus();
    }
    // Only when the menu first appears.
  }, [open, position === undefined]);

  useEffect(() => {
    if (active >= 0)
      itemRefs.current.get(active)?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const close = () => {
    // Focus would otherwise be lost with the menu; put it back on the trigger.
    if (menu.current?.contains(document.activeElement)) button.current?.focus();
    setOpen(false);
    setQuery('');
    setPosition(undefined);
  };

  const choose = (item: MenuItem) => {
    close();
    item.onSelect?.();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      if (!open) return;
      // Close the menu, not the dialog around it.
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!selectable.length) return;
      const pos = selectable.indexOf(active);
      const next =
        e.key === 'ArrowDown'
          ? selectable[(pos + 1) % selectable.length]
          : selectable[(pos - 1 + selectable.length) % selectable.length];
      setActive(next);
    } else if (e.key === 'Enter' && open) {
      const target =
        active >= 0
          ? visible[active]
          : selectable.length === 1
            ? visible[selectable[0]]
            : undefined;
      if (target) {
        e.preventDefault();
        choose(target);
      }
    }
  };

  return (
    <div
      className={`relative ${triggerClassName.includes('w-full') ? 'block w-full' : 'inline-block'}`}
      ref={root}
      onKeyDown={onKeyDown}
    >
      <button
        ref={button}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        disabled={disabled}
        aria-invalid={invalid}
        className={triggerClassName}
        onClick={(e) => {
          e.stopPropagation();
          setActive(-1);
          setQuery('');
          setPosition(undefined);
          setOpen((o) => !o);
        }}
      >
        {trigger(open)}
      </button>
      {open &&
        createPortal(
          <div
            ref={menu}
            role="menu"
            tabIndex={-1}
            style={position ?? { position: 'fixed', visibility: 'hidden' }}
            className={`z-50 ${fullWidth ? '' : widthClass} flex flex-col overflow-hidden border border-line bg-ink-850 shadow-[0_16px_40px_rgba(4,10,20,0.55)] focus:outline-none`}
          >
            {header && (
              <div className="border-b border-line px-3 py-2">{header}</div>
            )}
            {searchable && (
              <div className="relative border-b border-line p-2">
                <Search
                  size={14}
                  className="absolute left-4 top-[17px] text-fg-faint"
                />
                <input
                  ref={search}
                  className="input pl-8"
                  aria-label={searchPlaceholder}
                  placeholder={searchPlaceholder}
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setActive(-1);
                  }}
                />
              </div>
            )}
            <div
              className={`py-1 ${searchable ? 'max-h-64 overflow-y-auto' : ''}`}
            >
              {visible.map((item, i) =>
                item.divider ? (
                  <div
                    key={`d${i}`}
                    className="my-1 border-t border-line"
                    role="separator"
                  />
                ) : (
                  <button
                    key={item.id ?? item.label}
                    ref={(el) => {
                      if (el) itemRefs.current.set(i, el);
                      else itemRefs.current.delete(i);
                    }}
                    type="button"
                    role="menuitem"
                    disabled={item.disabled}
                    onMouseEnter={() => setActive(i)}
                    onClick={(e) => {
                      e.stopPropagation();
                      choose(item);
                    }}
                    className={`flex w-full items-center gap-2 border-l-2 px-3 py-1.5 text-left text-sm disabled:opacity-40 ${
                      active === i
                        ? 'border-azure bg-ink-800'
                        : 'border-transparent'
                    } ${item.danger ? 'text-deny' : 'text-fg'}`}
                  >
                    <span className="flex w-4 shrink-0 justify-center text-fg-muted">
                      {item.checked ? <Check size={14} /> : item.icon}
                    </span>
                    <span
                      className="flex-1 truncate"
                      title={
                        item.hint ? `${item.label} (${item.hint})` : item.label
                      }
                    >
                      {item.label}
                    </span>
                    {item.hint && (
                      <span className="shrink-0 text-xs text-fg-faint">
                        {item.hint}
                      </span>
                    )}
                  </button>
                ),
              )}
              {searchable && !selectable.length && (
                <p className="px-3 py-2 text-sm text-fg-faint">
                  Nothing matches “{query}”.
                </p>
              )}
            </div>
          </div>,
          document.body,
        )}
    </div>
  );
}

/** The "⋯" overflow menu used on rows and cards. */
export function EllipsisMenu({
  items,
  label = 'More actions',
}: {
  items: MenuItem[];
  label?: string;
}) {
  return (
    <Dropdown
      align="right"
      label={label}
      items={items}
      // Grows to fit the longest action rather than cutting it off.
      widthClass="w-max min-w-[12rem] max-w-sm"
      triggerClassName="flex h-7 w-7 items-center justify-center rounded text-fg-muted hover:bg-ink-800 hover:text-fg"
      trigger={() => <MoreHorizontal size={16} />}
    />
  );
}

/** Lists longer than this get a search box and a fixed-height scrolling list. */
const SEARCH_THRESHOLD = 8;

/** A select-style dropdown with a chevron and a truncated (ellipsized) current value. */
export function SelectMenu<T extends string>({
  value,
  options,
  onChange,
  placeholder = 'Select…',
  icon,
  widthClass = 'w-72',
  label,
  searchable,
  disabled,
  'aria-invalid': invalid,
}: {
  value?: T;
  options: { value: T; label: string; hint?: string; icon?: ReactNode }[];
  onChange: (value: T) => void;
  placeholder?: string;
  icon?: ReactNode;
  widthClass?: string;
  label?: string;
  /** Defaults to on for long lists. */
  searchable?: boolean;
  disabled?: boolean;
  'aria-invalid'?: boolean;
}) {
  const current = options.find((o) => o.value === value);
  return (
    <Dropdown
      label={label}
      disabled={disabled}
      aria-invalid={invalid}
      widthClass={widthClass}
      searchable={searchable ?? options.length > SEARCH_THRESHOLD}
      searchPlaceholder={label ? `Search ${label.toLowerCase()}…` : 'Search…'}
      triggerClassName={`${widthClass} flex h-8 items-center gap-2 rounded border border-line bg-ink-950 px-2.5 text-left text-sm hover:border-fg-faint disabled:cursor-not-allowed disabled:opacity-50`}
      trigger={(open) => (
        <>
          {icon && <span className="text-fg-muted">{icon}</span>}
          <span
            className={`flex-1 truncate ${current ? '' : 'text-fg-faint'}`}
            title={current?.label}
          >
            {current?.label ?? placeholder}
          </span>
          <ChevronDown
            size={14}
            className={`text-fg-muted transition-transform ${open ? 'rotate-180' : ''}`}
          />
        </>
      )}
      items={options.map((o) => ({
        id: o.value,
        label: o.label,
        hint: o.hint,
        icon: o.icon,
        checked: o.value === value,
        onSelect: () => onChange(o.value),
      }))}
    />
  );
}
