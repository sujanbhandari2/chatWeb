import { Navigate, Outlet } from 'react-router-dom';
import { AdminRoutes } from '../../constants/admin.constants';
import { useAdminAuthStore } from '../../store/useAdminAuthStore';
import './admin-shell.css';

export function AdminAuthGuard(): JSX.Element {
  const token = useAdminAuthStore((s) => s.token);
  const sessionHydrated = useAdminAuthStore((s) => s.sessionHydrated);

  if (!sessionHydrated) {
    return (
      <div className="admin-login-page">
        <p style={{ color: '#94a3b8' }}>Loading…</p>
      </div>
    );
  }

  if (!token?.trim()) {
    return <Navigate to={AdminRoutes.LOGIN} replace />;
  }

  return <Outlet />;
}
