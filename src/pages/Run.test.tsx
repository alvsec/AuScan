import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import "../i18n";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

import { useRunStore } from "../store/useRunStore";
import { Run } from "./Run";

describe("Run", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(undefined);
    useRunStore.setState({
      estado: "inactivo",
      lineas: [],
      runsTerminados: [],
      error: null,
      _desuscribir: null,
    });
  });

  it("no lanza sin escribir objetivos", () => {
    render(<Run />);
    expect(screen.getByRole("button", { name: /lanzar/i })).toBeDisabled();
  });

  it("pide confirmación mostrando el argv antes de lanzar", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    expect(screen.getByRole("dialog")).toHaveTextContent("198.51.100.5");
    expect(invoke).not.toHaveBeenCalled();
  });

  it("llama a run_start solo tras confirmar", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    await userEvent.click(screen.getByRole("button", { name: /^ejecutar$/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("run_start", {
        phase: "discovery",
        toolId: "nmap",
        targets: ["198.51.100.5"],
      });
    });
  });

  it("muestra las líneas de log acumuladas", () => {
    useRunStore.setState({
      estado: "corriendo",
      lineas: [{ origen: "stdout", texto: "hola" }],
    });
    render(<Run />);
    expect(screen.getByTestId("log")).toHaveTextContent("hola");
  });

  it("el botón de lanzar está deshabilitado mientras corre", () => {
    useRunStore.setState({ estado: "corriendo" });
    render(<Run />);
    expect(screen.getByRole("button", { name: /lanzar/i })).toBeDisabled();
  });

  it("el botón de cancelar ejecución llama a run_cancel", async () => {
    useRunStore.setState({ estado: "corriendo" });
    render(<Run />);
    await userEvent.click(screen.getByRole("button", { name: /cancelar ejecución/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("run_cancel");
    });
  });
});
