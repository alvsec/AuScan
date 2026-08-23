import { render, screen, waitFor } from "@testing-library/react";
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
    invoke.mockResolvedValue([]);
    useAppStore.setState({ scopeEntries: [], error: null });
  });

  it("avisa de que un CIDR con bits de host es ambiguo", async () => {
    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/rango o dirección/i), "198.51.100.5/24");
    expect(await screen.findByRole("alert")).toHaveTextContent(/ambiguo/i);
  });

  it("avisa de que un /0 es demasiado amplio", async () => {
    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/rango o dirección/i), "0.0.0.0/0");
    expect(await screen.findByRole("alert")).toHaveTextContent(/demasiado amplio/i);
  });

  it("previsualiza el veredicto con el espejo, sin llamar a Rust", async () => {
    invoke.mockResolvedValue([
      {
        id: 1,
        kind: "allow",
        family: "v4",
        cidr: "198.51.100.0/24",
        note: null,
        createdAt: "2026-08-22T10:00:00Z",
      },
    ]);

    render(<Scope />);
    await screen.findByText("198.51.100.0/24");
    await userEvent.type(screen.getByLabelText(/comprobar objetivo/i), "198.51.100.9");

    expect(await screen.findByText(/dentro de alcance/i)).toBeInTheDocument();
    // Puede haberse llamado a scope_list al montar; lo que no debe haber
    // ocurrido es una comprobación autoritativa contra Rust.
    expect(invoke).not.toHaveBeenCalledWith("scope_check", expect.anything());
  });

  it("dice que el alcance está vacío cuando no hay ninguna entrada", async () => {
    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/comprobar objetivo/i), "198.51.100.9");
    expect(await screen.findByText(/alcance vacío/i)).toBeInTheDocument();
  });

  it("permite crear una exclusión, no solo una autorización", async () => {
    render(<Scope />);
    await userEvent.click(screen.getByLabelText(/excluido/i));
    await userEvent.type(
      screen.getByLabelText(/rango o dirección/i),
      "198.51.100.128/25",
    );
    await userEvent.click(screen.getByRole("button", { name: /^añadir$/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("scope_add", {
        kind: "deny",
        entry: "198.51.100.128/25",
        note: null,
      });
    });
  });

  it("muestra el error del backend y conserva lo escrito si no se guardó", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "scope_add"
        ? Promise.reject("no hay ningún engagement abierto")
        : Promise.resolve([]),
    );

    render(<Scope />);
    const campo = screen.getByLabelText(/rango o dirección/i);
    await userEvent.type(campo, "198.51.100.0/24");
    await userEvent.click(screen.getByRole("button", { name: /^añadir$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/engagement abierto/i);
    expect(campo).toHaveValue("198.51.100.0/24");
  });

  it("carga el alcance al montar, sin depender de que se abriera antes", async () => {
    render(<Scope />);
    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("scope_list");
    });
  });
});
