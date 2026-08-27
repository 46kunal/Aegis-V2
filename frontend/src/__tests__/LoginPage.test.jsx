import { fireEvent, render, screen } from "@testing-library/react";
import { act } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";

import LoginPage from "../pages/LoginPage";

const loginMock = vi.fn();
const registerMock = vi.fn();

vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({
    isAuthenticated: false,
    login: loginMock,
    register: registerMock,
  }),
}));

describe("LoginPage", () => {
  beforeEach(() => {
    loginMock.mockReset();
    registerMock.mockReset();
  });

  it("submits login credentials", async () => {
    loginMock.mockResolvedValue({});

    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <LoginPage />
      </MemoryRouter>,
    );

    await act(async () => {
      fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "admin@example.com" } });
      fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "StrongPass123!" } });
      fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    });

    expect(loginMock).toHaveBeenCalledWith({
      email: "admin@example.com",
      password: "StrongPass123!",
    });
  });

  it("switches to register mode and submits registration payload", async () => {
    registerMock.mockResolvedValue({});

    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <LoginPage />
      </MemoryRouter>,
    );

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /register/i }));
    });

    const fullNameInput = await screen.findByLabelText(/full name/i);

    await act(async () => {
      fireEvent.change(fullNameInput, { target: { value: "Aegis Operator" } });
      fireEvent.change(screen.getByLabelText(/^email$/i), { target: { value: "ops@example.com" } });
      fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: "StrongPass123!" } });
      fireEvent.change(screen.getByLabelText(/role/i), { target: { value: "admin" } });
      fireEvent.click(screen.getByRole("button", { name: /create account/i }));
    });

    expect(registerMock).toHaveBeenCalledWith({
      email: "ops@example.com",
      password: "StrongPass123!",
      fullName: "Aegis Operator",
      role: "admin",
    });
  });
});
