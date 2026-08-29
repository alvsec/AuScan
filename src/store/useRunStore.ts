import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { create } from "zustand";

import { api } from "../data/runs";
import type { FaseTerminada, LineaLog, RunDone, RunError } from "../domain/model/run";

type EstadoRun = "inactivo" | "corriendo";

type RunStore = {
  estado: EstadoRun;
  lineas: LineaLog[];
  runsTerminados: RunDone[];
  recuentoFinal: FaseTerminada | null;
  error: string | null;
  iniciar: (phase: string, toolId: string, targets: string[]) => Promise<void>;
  cancelar: () => Promise<void>;
  _suscribir: () => Promise<UnlistenFn[]>;
  _desuscribir: UnlistenFn[] | null;
};

const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

// Buffer acotado: la spec exige que el log de la UI no crezca sin
// límite, aunque raw/ guarde siempre la salida completa.
const MAX_LINEAS = 500;

export const useRunStore = create<RunStore>((set, get) => ({
  estado: "inactivo",
  lineas: [],
  runsTerminados: [],
  recuentoFinal: null,
  error: null,
  _desuscribir: null,

  iniciar: async (phase, toolId, targets) => {
    get()._desuscribir?.forEach((unlisten) => unlisten());
    set({
      estado: "corriendo",
      lineas: [],
      runsTerminados: [],
      recuentoFinal: null,
      error: null,
      _desuscribir: null,
    });
    try {
      const unlisten = await get()._suscribir();
      set({ _desuscribir: unlisten });
      await api.start(phase, toolId, targets);
    } catch (e) {
      set({ error: mensaje(e), estado: "inactivo" });
    }
  },

  cancelar: async () => {
    try {
      await api.cancel();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  _suscribir: async () => {
    const unlistenLog = await listen<LineaLog>("run:log", (evento) => {
      set((s) => ({
        lineas: [...s.lineas, evento.payload].slice(-MAX_LINEAS),
      }));
    });
    const unlistenDone = await listen<RunDone>("run:done", (evento) => {
      set((s) => ({ runsTerminados: [...s.runsTerminados, evento.payload] }));
    });
    const unlistenFase = await listen<FaseTerminada>("run:fase-terminada", (evento) => {
      set({ estado: "inactivo", recuentoFinal: evento.payload });
    });
    // Los fallos que ocurren DESPUÉS de que `run_start` haya devuelto
    // (el objetivo fuera de alcance, sobre todo) no llegan como rechazo
    // de `invoke`: llegan por aquí. Sin este listener solo se veían como
    // una línea de stderr perdida en el log.
    const unlistenError = await listen<RunError>("run:error", (evento) => {
      set({ error: evento.payload.mensaje });
    });
    return [unlistenLog, unlistenDone, unlistenFase, unlistenError];
  },
}));
