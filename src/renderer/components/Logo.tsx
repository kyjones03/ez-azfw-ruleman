import { useId } from 'react';

const SHIELD = 'M32 4 L55 12 V33 C55 46 45 56 32 60 C19 56 9 46 9 33 V12 Z';

/** Original EZ AzFW Manager emblem: a shield with brickwork (firewall) and a flame.
 *  The app icon is generated from assets/icons/logo.svg; keep the two in sync. */
export function Logo({
  size = 32,
  className,
}: {
  size?: number;
  className?: string;
}) {
  const uid = useId().replace(/:/g, '');
  const shieldId = `shield-${uid}`;
  const flameId = `flame-${uid}`;
  const clipId = `clip-${uid}`;

  const rows = [
    { y: 24, offset: 0 },
    { y: 32, offset: 5 },
    { y: 40, offset: 0 },
  ];

  return (
    <svg
      viewBox="0 0 64 64"
      width={size}
      height={size}
      className={className}
      role="img"
      aria-label="EZ AzFW Manager logo"
    >
      <defs>
        <linearGradient id={shieldId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#50E6FF" />
          <stop offset="100%" stopColor="#0078D4" />
        </linearGradient>
        <linearGradient id={flameId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#FFB900" />
          <stop offset="100%" stopColor="#F25022" />
        </linearGradient>
        <clipPath id={clipId}>
          <path
            d={SHIELD}
            transform="translate(32 32) scale(0.82) translate(-32 -32)"
          />
        </clipPath>
      </defs>

      <path d={SHIELD} fill={`url(#${shieldId})`} />

      <g fill="white" fillOpacity={0.9} clipPath={`url(#${clipId})`}>
        {rows.map(({ y, offset }) =>
          Array.from({ length: 6 }, (_, i) => (
            <rect
              key={`${y}-${i}`}
              x={4 + offset + i * 10}
              y={y}
              width={8.5}
              height={6}
              rx={1}
            />
          )),
        )}
      </g>

      <path
        d="M32 7 C36 11 38 14 37 18 C36.5 20.5 34.5 22 32 22 C29.5 22 27.5 20.5 27 18 C26.5 15.5 28 13.5 29.5 12 C29.5 14 30.5 15.5 32 16 C31 13 31 10 32 7 Z"
        fill={`url(#${flameId})`}
      />
    </svg>
  );
}
