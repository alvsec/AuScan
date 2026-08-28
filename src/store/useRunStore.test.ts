import { beforeEach, describe, expect, it, vi } from "vitest";

// `invoke` sigue el mismo patrón `vi.hoisted` que Preflight.test.tsx,
// Scope.test.tsx y Engagements.test.tsx ya usan para mockear
// "@tauri-apps/api/core" en este proyecto.
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

// No hay ningún mock previo de "@tauri-apps/api/event" en este proyecto
// (ningún otro store/página escucha eventos todavía), así que no hay un
// patrón establecido que seguir aquí. `listeners` guarda el callback que
// el store registra con `listen(nombre, cb)` para poder dispararlo a mano
// desde el test, como si el backend hubiera emitido el evento.
const listeners: Record<string, (evento: { payload: unknown }) => void> = {};
const unlistenMocks: Record<string, ReturnType<typeof vi.fn>> = {};

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((nombre: string, cb: (evento: { payload: unknown }) => void) => {
    listeners[nombre] = cb;
    const unlisten = vi.fn(() => {
      delete listeners[nombre];
    });
    unlistenMocks[nombre] = unlisten;
    return Promise.resolve(unlisten);
  }),
}));

import { useRunStore } from "./useRunStore";

describe("useRunStore", () => {
  beforeEach(() => {
    useRunStore.setState({ estado: "inactivo", lineas: [], runsTerminados: [], error: null, _desuscribir: null });
    invoke.mockReset();
  });

  it("pasa a corriendo y limpia el estado anterior al iniciar", async () => {
    invoke.mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["198.51.100.5"]);
    expect(useRunStore.getState().estado).toBe("corriendo");
    expect(useRunStore.getState().lineas).toEqual([]);
  });

  it("acumula líneas de log según llegan por el evento run:log", async () => {
    invoke.mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["198.51.100.5"]);
    listeners["run:log"]!({ payload: { origen: "stdout", texto: "hola" } });
    expect(useRunStore.getState().lineas).toEqual([{ origen: "stdout", texto: "hola" }]);
  });

  it("vuelve a inactivo cuando llega run:fase-terminada", async () => {
    invoke.mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["198.51.100.5"]);
    listeners["run:fase-terminada"]!({ payload: undefined });
    expect(useRunStore.getState().estado).toBe("inactivo");
  });

  it("guarda el error y vuelve a inactivo si start falla", async () => {
    invoke.mockRejectedValue("fuera de alcance");
    await useRunStore.getState().iniciar("discovery", "nmap", ["203.0.113.9"]);
    expect(useRunStore.getState().error).toBe("fuera de alcance");
    expect(useRunStore.getState().estado).toBe("inactivo");
  });

  // El test de arriba cubre el rechazo SÍNCRONO de `invoke`, que es el
  // único camino que `iniciar()` maneja en su try/catch. Pero un objetivo
  // fuera de alcance no llega así: `run_start` devuelve Ok y el fallo se
  // descubre después, ya dentro de la tarea del backend, que lo emite por
  // `run:error`. Ese camino es el que de verdad usa el rechazo más
  // importante que hace esta aplicación.
  it("guarda el error cuando llega por el evento run:error", async () => {
    invoke.mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["203.0.113.9"]);
    listeners["run:error"]!({ payload: { mensaje: "objetivo fuera de alcance: 203.0.113.9" } });
    expect(useRunStore.getState().error).toBe("objetivo fuera de alcance: 203.0.113.9");
  });

  it("cancela las suscripciones anteriores si iniciar() se llama de nuevo", async () => {
    invoke.mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["198.51.100.5"]);
    const unlistenPrevio = unlistenMocks["run:log"];
    await useRunStore.getState().iniciar("services", "nmap", ["198.51.100.5"]);
    expect(unlistenPrevio).toHaveBeenCalledTimes(1);
  });
});
