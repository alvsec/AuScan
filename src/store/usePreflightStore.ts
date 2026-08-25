import { create } from "zustand";

import { preflightApi } from "../data/preflight";
import type { PreflightReport } from "../domain/model/preflight";

type PreflightStore = {
  report: PreflightReport | null;
  loading: boolean;
  error: string | null;
  installing: string | null;
  run: () => Promise<void>;
  install: (toolId: string) => Promise<void>;
};

const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

// Store separado de useAppStore: preflight no depende de ningún
// engagement abierto, es una comprobación global de la máquina.
export const usePreflightStore = create<PreflightStore>((set, get) => ({
  report: null,
  loading: false,
  error: null,
  installing: null,

  run: async () => {
    set({ loading: true, error: null });
    try {
      set({ report: await preflightApi.run(), loading: false });
    } catch (e) {
      set({ error: mensaje(e), loading: false });
    }
  },

  install: async (toolId) => {
    set({ installing: toolId, error: null });
    try {
      await preflightApi.install(toolId);
      await get().run();
    } catch (e) {
      set({ error: mensaje(e) });
    } finally {
      set({ installing: null });
    }
  },
}));
