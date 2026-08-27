import { Navigate } from "react-router-dom";

import { useAuth } from "../hooks/useAuth";

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading, devMode } = useAuth();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-cyber-950 text-cyber-200">
        Establishing secure session...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <>
      {devMode && (
        <div
          style={{
            background: "linear-gradient(90deg, #f59e0b, #ef4444)",
            color: "#fff",
            textAlign: "center",
            padding: "6px 12px",
            fontSize: "13px",
            fontWeight: 700,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            position: "sticky",
            top: 0,
            zIndex: 9999,
          }}
        >
          ⚠ DEV MODE — AUTH DISABLED ⚠
        </div>
      )}
      {children}
    </>
  );
}
