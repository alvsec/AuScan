import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import "../i18n";
import { useAppStore } from "../store/useAppStore";
import { Scope } from "./Scope";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

describe("Scope", () => {
  beforeEach(() => {
    invoke.mockReset();
    useAppStore.setState({ scopeEntries: [], error: null });
  });

  it("avisa de que un CIDR con bits de host es ambiguo", async () => {
    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/autorizado/i), "198.51.100.5/24");
    expect(await screen.findByRole("alert")).toHaveTextContent(/ambiguo/i);
  });

  it("avisa de que un /0 es demasiado amplio", async () => {
    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/autorizado/i), "0.0.0.0/0");
    expect(await screen.findByRole("alert")).toHaveTextContent(/demasiado amplio/i);
  });

  it("previsualiza el veredicto con el espejo, sin llamar a Rust", async () => {
    useAppStore.setState({
      scopeEntries: [
        {
          id: 1,
          kind: "allow",
          family: "v4",
          cidr: "198.51.100.0/24",
          note: null,
          createdAt: "2026-08-22T10:00:00Z",
        },
      ],
    });

    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/comprobar objetivo/i), "198.51.100.9");

    expect(await screen.findByText(/dentro de alcance/i)).toBeInTheDocument();
    expect(invoke).not.toHaveBeenCalled();
  });

  it("dice que el alcance está vacío cuando no hay ninguna entrada", async () => {
    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/comprobar objetivo/i), "198.51.100.9");
    expect(await screen.findByText(/alcance vacío/i)).toBeInTheDocument();
  });
});
