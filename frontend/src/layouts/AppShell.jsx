import { NavLink, useNavigate } from "react-router-dom";

import { useAuth } from "../hooks/useAuth";

const navItems = [
  { label: "Dashboard", path: "/dashboard" },
  { label: "Topology", path: "/topology" },
  { label: "Assets", path: "/assets" },
  { label: "Scans", path: "/scans" },
  { label: "Findings", path: "/findings" },
  { label: "Reports", path: "/reports" },
  { label: "Settings", path: "/settings" },
];

export default function AppShell({ children }) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen md:flex">
      <aside className="glass-panel text-grid md:sticky md:top-0 md:h-screen md:w-72">
        <div className="border-b border-cyber-700 px-6 py-5">
          <p className="font-display text-2xl font-bold tracking-[0.16em] text-cyber-200">AEGIS V2</p>
          <p className="mt-2 text-xs uppercase tracking-[0.22em] text-cyber-400">Security Control Plane</p>
        </div>

        <nav className="space-y-2 px-3 py-5">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `block rounded-md px-3 py-2 text-sm font-semibold transition ${
                  isActive
                    ? "bg-cyber-500 text-cyber-100 shadow-scanner"
                    : "text-cyber-300 hover:bg-cyber-700 hover:text-cyber-100"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-8 border-t border-cyber-700 px-6 py-4 text-sm text-cyber-300">
          <p className="font-semibold text-cyber-100">{user?.full_name}</p>
          <p className="text-cyber-400">{user?.email}</p>
          <button type="button" className="btn-secondary mt-4 w-full" onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 p-5 md:p-8">{children}</main>
    </div>
  );
}
