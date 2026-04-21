import { useEffect, useMemo, useState, type ReactNode } from 'react';
import './admin-layout.css';

export type AdminNavId = 'dashboard' | 'tenants';

export type AdminLayoutProps = {
  activeNav: AdminNavId;
  onNavigate: (id: AdminNavId) => void;
  headerTitle: string;
  userLabel: string;
  onLogout: () => void;
  children: ReactNode;
};

function DashboardIcon(): JSX.Element {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z"
      />
    </svg>
  );
}

function TenantsIcon(): JSX.Element {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M16 11c1.66 0 3-1.34 3-3S17.66 5 16 5s-3 1.34-3 3 1.34 3 3 3ZM8 11c1.66 0 3-1.34 3-3S9.66 5 8 5 5 6.34 5 8s1.34 3 3 3Zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5C15 14.17 10.33 13 8 13Zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5C23 14.17 18.33 13 16 13Z"
      />
    </svg>
  );
}

const NAV: Array<{ id: AdminNavId; label: string; icon: () => JSX.Element }> = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
  { id: 'tenants', label: 'Tenants', icon: TenantsIcon }
];

export function AdminLayout({
  activeNav,
  onNavigate,
  headerTitle,
  userLabel,
  onLogout,
  children
}: AdminLayoutProps): JSX.Element {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSidebarOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 768px)');
    const apply = () => setIsMobile(mq.matches);
    apply();
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, []);

  const hamburgerLabel = useMemo(() => {
    if (isMobile) {
      return sidebarOpen ? 'Close navigation' : 'Open navigation';
    }
    return sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation';
  }, [isMobile, sidebarOpen, sidebarCollapsed]);

  return (
    <div className="va-admin-root">
      <div className="va-admin-shell">
        <div
          className={`va-admin-sidebar-overlay${sidebarOpen ? ' va-admin-sidebar-overlay--open' : ''}`}
          role="presentation"
          onClick={() => setSidebarOpen(false)}
        />
        <aside
          className={`va-admin-sidebar${
            sidebarOpen ? ' va-admin-sidebar--open' : ''
          }${sidebarCollapsed ? ' va-admin-sidebar--collapsed' : ''}`}
          aria-label="Admin navigation"
        >
          <div className="va-admin-sidebar-brand">
            <span className="va-admin-sidebar-brand-text">Vitafy Admin</span>
            <button
              type="button"
              className="va-admin-sidebar-hamburger"
              aria-label={hamburgerLabel}
              aria-expanded={isMobile ? sidebarOpen : !sidebarCollapsed}
              onClick={() => {
                if (isMobile) {
                  setSidebarOpen(false);
                  return;
                }
                setSidebarCollapsed((v) => !v);
              }}
            >
              <span className="va-admin-hamburger-bars" aria-hidden="true" />
            </button>
          </div>
          <nav className="va-admin-sidebar-nav">
            {NAV.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`va-admin-nav-btn${activeNav === item.id ? ' va-admin-nav-btn--active' : ''}`}
                title={sidebarCollapsed ? item.label : undefined}
                onClick={() => {
                  onNavigate(item.id);
                  setSidebarOpen(false);
                }}
              >
                <span className="va-admin-nav-icon" aria-hidden="true">
                  <item.icon />
                </span>
                <span className="va-admin-nav-label">{item.label}</span>
              </button>
            ))}
          </nav>
        </aside>
        <div className="va-admin-main">
          <header className="va-admin-header">
            <div className="va-admin-header-left">
              <h1 className="va-admin-header-title">{headerTitle}</h1>
            </div>
            <div className="va-admin-header-meta">
              <span>{userLabel}</span>
              <button type="button" className="va-admin-logout" onClick={onLogout}>
                Log out
              </button>
            </div>
          </header>
          <main className="va-admin-content">{children}</main>
        </div>
      </div>
    </div>
  );
}
