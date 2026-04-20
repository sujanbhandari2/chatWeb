export function AdminDashboardView(): JSX.Element {
  return (
    <div className="va-admin-panel">
      <h2>Dashboard</h2>
      <p>
        You are signed in to the Vitafy admin console. Use <strong>Tenants</strong> in the sidebar to
        manage tenant accounts when that screen is wired to the admin API.
      </p>
    </div>
  );
}
