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
      elevar: false,
    });
    // La vista previa no ejecuta nada: hasta confirmar, `run_start` no se
    // ha llamado ni una vez.
    expect(invoke).not.toHaveBeenCalledWith("run_start", expect.anything());
  });

  it("pide la vista previa con elevar=true si la casilla está marcada", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByLabelText(/elevar esta fase/i));
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("run_preview", {
        phase: "discovery",
        toolId: "nmap",
        targets: ["198.51.100.5"],
        elevar: true,
      });
    });
  });

  it("no eleva por defecto", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith(
        "run_preview",
        expect.objectContaining({ elevar: false }),
      );
    });
  });

  // El diálogo enseña el argv real de `run_preview`; si `elevar` pudiera
  // cambiar entre la vista previa y `run_start` -- p.ej. porque el
  // operador la desmarca con el diálogo ya abierto -- la confirmación
  // mentiría igual que mentiría si se pudiera cambiar fase/objetivos, así
  // que la casilla se congela con las mismas tres condiciones.
  it("congela la casilla de elevar mientras el diálogo de confirmación está abierto", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    await screen.findByRole("dialog");
    expect(screen.getByLabelText(/elevar esta fase/i)).toBeDisabled();
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

  // El diálogo tiene que ser modal de verdad: `lanzar()` lee el estado
  // VIVO de fase y objetivos, no aquel con el que se calculó el argv que
  // se está enseñando. Si se pudieran editar con el diálogo abierto, el
  // operador vería el argv de A y lanzaría B.
  it("congela fase y objetivos mientras el diálogo de confirmación está abierto", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    await screen.findByRole("dialog");
    expect(screen.getByLabelText(/objetivos/i)).toBeDisabled();
    expect(screen.getByLabelText(/^fase$/i)).toBeDisabled();
  });

  it("vuelve a dejar editar tras cancelar la confirmación", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    await userEvent.click(await screen.findByRole("button", { name: /cancelar edición/i }));

    expect(screen.getByLabelText(/objetivos/i)).toBeEnabled();
    expect(screen.getByLabelText(/^fase$/i)).toBeEnabled();
  });

  // `run_preview` valida el alcance en el backend, y eso resuelve DNS:
  // la ida y vuelta puede tardar. Hasta que resuelve, `confirmando` sigue
  // en false y el botón seguía ahí, pulsable.
  it("deshabilita el botón de lanzar mientras la vista previa está en vuelo", async () => {
    let resolver!: (lineas: string[]) => void;
    despachar(
      () =>
        new Promise<string[]>((res) => {
          resolver = res;
        }),
    );
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    expect(screen.getByRole("button", { name: /lanzar/i })).toBeDisabled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // Mientras la vista previa está en vuelo, `confirmando` sigue en
    // false -- si los campos no se congelasen aquí también, el operador
    // podría reescribir el objetivo mientras espera y lanzar contra un
    // valor distinto del que acabará viendo en el diálogo.
    expect(screen.getByLabelText(/objetivos/i)).toBeDisabled();
    expect(screen.getByLabelText(/^fase$/i)).toBeDisabled();

    // Insistir no encadena una segunda vista previa en vuelo.
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    expect(invoke).toHaveBeenCalledTimes(1);

    resolver(ARGV_PREVISTO);
    expect(await screen.findByRole("dialog")).toHaveTextContent("198.51.100.5");
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
    // El `finally` que limpia `cargandoPrevisualizacion` tiene que
    // correr también en el camino de error -- si se moviera dentro del
    // `try`, el fallo más común (objetivo fuera de alcance) dejaría el
    // botón muerto para siempre sin que ningún otro test lo notase.
    expect(screen.getByRole("button", { name: /lanzar/i })).toBeEnabled();
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
        elevar: false,
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

  // Un fallo a mitad de fase corta `ejecutar_fase` antes de que acumule
  // nada, así que el camino de error de `run_start` emite
  // "run:fase-terminada" con ceros cableados -- pero las invocaciones que
  // sí terminaron antes del fallo ya escribieron filas reales. Enseñar
  // «0 hosts, 0 servicios, 0 observaciones» bajo el error sería mentir
  // sobre el expediente.
  it("no enseña recuento cuando la ejecución terminó en error", () => {
    useRunStore.setState({
      estado: "inactivo",
      error: "objetivo fuera de alcance: 203.0.113.9",
      recuentoFinal: { hosts: 0, servicios: 0, observaciones: 0 },
    });
    render(<Run />);
    expect(screen.getByRole("alert")).toHaveTextContent("objetivo fuera de alcance: 203.0.113.9");
    expect(screen.queryByText(/observaciones/i)).not.toBeInTheDocument();
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
