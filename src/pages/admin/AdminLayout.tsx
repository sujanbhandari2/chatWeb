import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';
import { AdminRoutes } from '../../constants/admin.constants';
import { WIDGET_PUBLIC_PATHS } from '../../constants/widget.constants';
import { useAdminProfileQuery } from '../../services/admin.service';
import { useAdminAuthStore } from '../../store/useAdminAuthStore';
import './admin-shell.css';

function profileEmail(profile: unknown): string {
  if (!profile || typeof profile !== 'object') {
    return '';
  }
  const o = profile as Record<string, unknown>;
  return typeof o.email === 'string' ? o.email : '';
}

export function AdminLayout(): JSX.Element {
  const clearSession = useAdminAuthStore((s) => s.clearSession);
  const navigate = useNavigate();
  const { data: profile } = useAdminProfileQuery();
  const email = profileEmail(profile);

  return (
    <div className="admin-shell">
      <aside className="admin-shell__sidebar">
        <p className="admin-shell__brand">Vitafy Admin</p>
        <p className="admin-shell__tag">Console</p>
        <nav className="admin-shell__nav">
          <NavLink to={AdminRoutes.CLIENTS}>Clients</NavLink>
          <NavLink to={WIDGET_PUBLIC_PATHS.EMBED_DOCS}>Widget embed guide</NavLink>
        </nav>
        <div className="admin-shell__sidebar-footer">
          {email ? <div style={{ color: '#94a3b8', marginBottom: '0.35rem' }}>{email}</div> : null}
          <div>
            <Link to="/">← Chat app</Link>
          </div>
          <button
            type="button"
            className="admin-sidebar-logout"
            onClick={() => {
              clearSession();
              navigate(AdminRoutes.LOGIN, { replace: true });
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="admin-shell__main">
        <Outlet />
      </main>
    </div>
  );
}
