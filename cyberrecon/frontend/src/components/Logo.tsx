export function Logo({ size = 28, showText = true }: { size?: number; showText?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <svg width={size} height={size} viewBox="0 0 32 32" role="img" aria-label="CyberRecon logo">
        <rect width="32" height="32" rx="8" fill="#141c19" stroke="#26332e" />
        <circle cx="16" cy="16" r="2.8" fill="#2fbf8f" />
        <circle cx="16" cy="16" r="7.5" fill="none" stroke="#2fbf8f" strokeOpacity=".7" strokeWidth="1.6" />
        <circle cx="16" cy="16" r="12" fill="none" stroke="#3db8d4" strokeOpacity=".55" strokeWidth="1.6" strokeDasharray="3.2 3.2" />
        <circle cx="25.5" cy="9" r="1.7" fill="#3db8d4" />
      </svg>
      {showText && <span className="font-display text-[17px] font-semibold tracking-tight">CyberRecon</span>}
    </span>
  );
}
