export type SidebarHeaderProps = {
  title: string;
  subtitle: string;
  onBack: () => void;
  backDisabled?: boolean;
  /** Defaults to "Back to chats". */
  backAriaLabel?: string;
};

/** Header for people / new group / edit group rails with back control. */
export function SidebarHeader({
  title,
  subtitle,
  onBack,
  backDisabled = false,
  backAriaLabel = 'Back to chats',
}: SidebarHeaderProps): JSX.Element {
  return (
    <div className="left-header left-header--widget-people">
      <button
        type="button"
        className="widget-people-back"
        onClick={onBack}
        disabled={backDisabled}
        aria-label={backAriaLabel}
      >
        ←
      </button>
      <div className="left-header-main">
        <h2>{title}</h2>
        <p className="widget-people-subtitle">{subtitle}</p>
      </div>
    </div>
  );
}
