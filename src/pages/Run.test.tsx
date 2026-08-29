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

// El argv que devolvería `run_preview`: banderas reales que el frontend
// no conoce ni construye. Que el diálogo enseñe ESTO y no algo armado en
// la webview es justo lo que se está probando.
const ARGV_PREVISTO = ["nmap -sn -PR -n -oX - 198.51.100.5"];

// `invoke` tiene que distinguir dos comandos desde que existe la vista
// previa, así que se despacha por nombre igual que hace Preflight.test.tsx.
const despachar = (previa: () => Promise<unknown>) =>
  invoke.mockImplementation((cmd: string) =>
    cmd === "run_preview" ? previa() : Promise.resolve(undefined),
  );

describe("Run", () => {
  beforeEach(() => {
    invoke.mockReset();
    despachar(() => Promise.resolve(ARGV_PREVISTO));
    useRunStore.setState({
      estado: "inactivo",
      lineas: [],
      runsTerminados: [],
      recuentoFinal: null,
      error: null,
      _desuscribir: null,
    });
  });

  it("no lanza sin escribir objetivos", () => {
    render(<Run />);
    expect(screen.getByRole("button", { name: /lanzar/i })).toBeDisabled();
  });

  it("pide confirmación mostrando el argv real que devuelve el backend", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    const dialogo = await screen.findByRole("dialog");
    expect(dialogo).toHaveTextContent("nmap -sn -PR -n -oX - 198.51.100.5");
    expect(invoke).toHaveBeenCalledWith("run_preview", {
      phase: "discovery",
      toolId: "nmap",
      targets: ["198.51.100.5"],
    });
    // La vista previa no ejecuta nada: hasta confirmar, `run_start` no se
    // ha llamado ni una vez.
    expect(invoke).not.toHaveBeenCalledWith("run_start", expect.anything());
  });

  it("enseña una línea por invocación cuando la fase planifica varias", async () => {
    despachar(() =>
      Promise.resolve(["nmap -sV -oX - 198.51.100.5", "nmap -sV -oX - 198.51.100.6"]),
    );
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.0/24");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    const lista = await screen.findByTestId("previsualizacion");
    expect(lista.querySelectorAll("li")).toHaveLength(2);
    expect(lista).toHaveTextContent("198.51.100.6");
  });

  it("no abre el diálogo si la vista previa falla", async () => {
    despachar(() => Promise.reject("objetivo fuera de alcance: 203.0.113.9"));
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "203.0.113.9");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "objetivo fuera de alcance: 203.0.113.9",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(invoke).not.toHaveBeenCalledWith("run_start", expect.anything());
  });

  it("llama a run_start solo tras confirmar", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    await userEvent.click(await screen.findByRole("button", { name: /^ejecutar$/i }));

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

  it("no enseña recuento hasta que la fase termina", () => {
    useRunStore.setState({ estado: "corriendo" });
    render(<Run />);
    expect(screen.queryByText(/observaciones/i)).not.toBeInTheDocument();
  });

  it("enseña el recuento de lo archivado al terminar la fase", () => {
    useRunStore.setState({
      estado: "inactivo",
      recuentoFinal: { hosts: 3, servicios: 7, observaciones: 11 },
    });
    render(<Run />);
    expect(screen.getByText("3 hosts, 7 servicios, 11 observaciones")).toBeInTheDocument();
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
