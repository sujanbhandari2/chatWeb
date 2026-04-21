import { useMemo, useState } from 'react';
import { AdminLayout, type AdminNavId } from '../../common/layout/AdminLayout';
import { useAdminAuthStore } from '../../store/useAdminAuthStore';
import { useAdminProfileQuery } from '../../services/admin.service';
import { AdminDashboardView } from './AdminDashboardView';
import { AdminLoginView } from './AdminLoginView';
import { AdminTenantsView } from './AdminTenantsView';

const TITLES: Record<AdminNavId, string> = {
  dashboard: 'Dashboard',
  tenants: 'Tenants'
};

export function AdminApp(): JSX.Element {
  const token = useAdminAuthStore((s) => s.token);
  const user = useAdminAuthStore((s) => s.user);
  const clearSession = useAdminAuthStore((s) => s.clearSession);
  const [nav, setNav] = useState<AdminNavId>('dashboard');

  const { data: profile } = useAdminProfileQuery();

  const userLabel = useMemo(() => {
    const email = profile?.email ?? user?.email;
    const name = profile?.name ?? user?.name;
    if (name && email) {
      return `${name} · ${email}`;
    }
    return email ?? 'Signed in';
  }, [profile, user]);

  if (!token || !user) {
    return <AdminLoginView />;
  }

  return (
    <AdminLayout
      activeNav={nav}
      onNavigate={setNav}
      headerTitle={TITLES[nav]}
      userLabel={userLabel}
      onLogout={() => clearSession()}
    >
      {nav === 'dashboard' ? <AdminDashboardView /> : <AdminTenantsView />}
    </AdminLayout>
  );
}
