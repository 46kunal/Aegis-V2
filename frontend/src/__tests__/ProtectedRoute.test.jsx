import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";

import ProtectedRoute from "../components/ProtectedRoute";

const authState = vi.hoisted(() => ({
  isAuthenticated: true,
  isLoading: false,
}));

vi.mock("../hooks/useAuth", () => ({
  useAuth: () => authState,
}));

describe("ProtectedRoute", () => {
  beforeEach(() => {
    authState.isAuthenticated = true;
    authState.isLoading = false;
  });

  it("renders children when authenticated", () => {
    render(
      <MemoryRouter initialEntries={["/protected"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route
            path="/protected"
            element={
              <ProtectedRoute>
                <div>Secret View</div>
              </ProtectedRoute>
            }
          />
          <Route path="/login" element={<div>Login Screen</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Secret View")).toBeInTheDocument();
  });

  it("redirects to login when not authenticated", () => {
    authState.isAuthenticated = false;
    authState.isLoading = false;

    render(
      <MemoryRouter initialEntries={["/protected"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route
            path="/protected"
            element={
              <ProtectedRoute>
                <div>Secret View</div>
              </ProtectedRoute>
            }
          />
          <Route path="/login" element={<div>Login Screen</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Login Screen")).toBeInTheDocument();
  });
});
