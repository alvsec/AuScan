import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import "../i18n";
import { useRunStore } from "../store/useRunStore";
import { Run } from "./Run";

// A diferencia de Preflight.test.tsx/Scope.test.tsx (que usan el store
// real y solo mockean `invoke`), aquí se mockea el módulo entero de
// useRunStore. useRunStore.test.ts ya cubre a fondo la suscripción a
// eventos y el ciclo de vida async del store; este test solo necesita
// tratar su interfaz pública como frontera para probar Run.tsx (diálogo
// de confirmación, estados deshabilitados, render del log).
vi.mock("../store/useRunStore");

const storeBase = {
  estado: "inactivo" as const,
  lineas: [],
  runsTerminados: [],
  error: null,
  iniciar: vi.fn(),
  cancelar: vi.fn(),
};

describe("Run", () => {
  beforeEach(() => {
    // Limpia el historial de llamadas de storeBase.iniciar/cancelar entre
    // tests: al ser el mismo objeto (y las mismas funciones vi.fn())
    // reutilizado con spread en cada mockReturnValue, sin esto las
    // aserciones "not.toHaveBeenCalled()" dependerían del orden de
    // ejecución de los tests.
    vi.clearAllMocks();
    vi.mocked(useRunStore).mockReturnValue({ ...storeBase });
  });

  it("no lanza sin escribir objetivos", () => {
    render(<Run />);
    expect(screen.getByRole("button", { name: /lanzar/i })).toBeDisabled();
  });

  it("pide confirmación mostrando el argv antes de lanzar", () => {
    render(<Run />);
    fireEvent.change(screen.getByLabelText(/objetivos/i), {
      target: { value: "198.51.100.5" },
    });
    fireEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    expect(screen.getByRole("dialog")).toHaveTextContent("198.51.100.5");
    expect(storeBase.iniciar).not.toHaveBeenCalled();
  });

  it("llama a iniciar solo tras confirmar", () => {
    render(<Run />);
    fireEvent.change(screen.getByLabelText(/objetivos/i), {
      target: { value: "198.51.100.5" },
    });
    fireEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    fireEvent.click(screen.getByRole("button", { name: /^ejecutar$/i }));
    expect(storeBase.iniciar).toHaveBeenCalledWith("discovery", "nmap", ["198.51.100.5"]);
  });

  it("muestra las líneas de log acumuladas", () => {
    vi.mocked(useRunStore).mockReturnValue({
      ...storeBase,
      estado: "corriendo",
      lineas: [{ origen: "stdout", texto: "hola" }],
    });
    render(<Run />);
    expect(screen.getByTestId("log")).toHaveTextContent("hola");
  });

  it("el botón de cancelar ejecución llama a cancelar", () => {
    vi.mocked(useRunStore).mockReturnValue({ ...storeBase, estado: "corriendo" });
    render(<Run />);
    fireEvent.click(screen.getByRole("button", { name: /cancelar ejecución/i }));
    expect(storeBase.cancelar).toHaveBeenCalled();
  });
});
