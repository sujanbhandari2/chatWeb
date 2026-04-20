import type { ReactNode } from 'react';
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

const NAV: Array<{ id: AdminNavId; label: string }> = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'tenants', label: 'Tenants' }
];

export function AdminLayout({
  activeNav,
  onNavigate,
  headerTitle,
  userLabel,
  onLogout,
  children
}: AdminLayoutProps): JSX.Element {
  return (
    <div className="va-admin-root">
      <div className="va-admin-shell">
        <aside className="va-admin-sidebar" aria-label="Admin navigation">
          <div className="va-admin-sidebar-brand">Vitafy Admin</div>
          <nav className="va-admin-sidebar-nav">
            {NAV.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`va-admin-nav-btn${activeNav === item.id ? ' va-admin-nav-btn--active' : ''}`}
                onClick={() => onNavigate(item.id)}
              >
                {item.label}
              </button>
            ))}
          </nav>
        </aside>
        <div className="va-admin-main">
          <header className="va-admin-header">
            <h1 className="va-admin-header-title">{headerTitle}</h1>
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
