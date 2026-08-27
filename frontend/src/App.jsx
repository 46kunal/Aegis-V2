import { Navigate, Route, Routes } from "react-router-dom";

import ProtectedRoute from "./components/ProtectedRoute";
import AppShell from "./layouts/AppShell";
import AssetsPage from "./pages/AssetsPage";
import DashboardPage from "./pages/DashboardPage";
import FindingsPage from "./pages/FindingsPage";
import LoginPage from "./pages/LoginPage";
import ReportsPage from "./pages/ReportsPage";
import ScansPage from "./pages/ScansPage";
import SettingsPage from "./pages/SettingsPage";
import TopologyPage from "./pages/TopologyPage";

function ProtectedLayout({ children }) {
  return (
    <ProtectedRoute>
      <AppShell>{children}</AppShell>
    </ProtectedRoute>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedLayout>
            <DashboardPage />
          </ProtectedLayout>
        }
      />
      <Route
        path="/assets"
        element={
          <ProtectedLayout>
            <AssetsPage />
          </ProtectedLayout>
        }
      />
      <Route
        path="/scans"
        element={
          <ProtectedLayout>
            <ScansPage />
          </ProtectedLayout>
        }
      />
      <Route
        path="/findings"
        element={
          <ProtectedLayout>
            <FindingsPage />
          </ProtectedLayout>
        }
      />
      <Route
        path="/reports"
        element={
          <ProtectedLayout>
            <ReportsPage />
          </ProtectedLayout>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedLayout>
            <SettingsPage />
          </ProtectedLayout>
        }
      />
      <Route
        path="/topology"
        element={
          <ProtectedLayout>
            <TopologyPage />
          </ProtectedLayout>
        }
      />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
