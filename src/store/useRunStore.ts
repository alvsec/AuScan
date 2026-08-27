import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { create } from "zustand";

import { api } from "../data/runs";
import type { LineaLog, RunDone } from "../domain/model/run";

type EstadoRun = "inactivo" | "corriendo";

type RunStore = {
  estado: EstadoRun;
  lineas: LineaLog[];
  runsTerminados: RunDone[];
  error: string | null;
  iniciar: (phase: string, toolId: string, targets: string[]) => Promise<void>;
  cancelar: () => Promise<void>;
  _suscribir: () => Promise<UnlistenFn[]>;
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
  error: null,

  iniciar: async (phase, toolId, targets) => {
    set({ estado: "corriendo", lineas: [], runsTerminados: [], error: null });
    await get()._suscribir();
    try {
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
    const unlistenFase = await listen("run:fase-terminada", () => {
      set({ estado: "inactivo" });
    });
    return [unlistenLog, unlistenDone, unlistenFase];
  },
}));
