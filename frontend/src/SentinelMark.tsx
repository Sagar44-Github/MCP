type SentinelMarkProps = { className?: string }

export default function SentinelMark({ className }: SentinelMarkProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 40 40"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M20 3.5 33 9v9.4c0 8.4-5.2 14.8-13 18.1C12.2 33.2 7 26.8 7 18.4V9l13-5.5Z"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path
        d="M12 15.5h6l3 4.5h7M12 24.5h6l3-4.5"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="11.5" cy="15.5" r="2" fill="currentColor" />
      <circle cx="11.5" cy="24.5" r="2" fill="currentColor" />
      <circle cx="28" cy="20" r="2.2" fill="currentColor" />
      <path d="M20 11.5v3" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      <circle cx="20" cy="9.5" r="1.4" fill="currentColor" />
    </svg>
  )
}
