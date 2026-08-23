import { create } from "zustand";

import { api } from "../data/engagements";
import type { EngagementRef, ScopeEntry, ScopeKind } from "../domain/model/types";

type AppStore = {
  engagements: EngagementRef[];
  current: EngagementRef | null;
  scopeEntries: ScopeEntry[];
  error: string | null;
  load: () => Promise<void>;
  create: (codename: string) => Promise<void>;
  open: (id: string) => Promise<void>;
  purge: (id: string) => Promise<void>;
  loadScope: () => Promise<void>;
  addScope: (kind: ScopeKind, entry: string) => Promise<boolean>;
  removeScope: (id: number) => Promise<void>;
};

// Los errores de Rust llegan ya serializados como cadena (el Serialize de
// AppError emite su Display), así que se muestran tal cual.
const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

export const useAppStore = create<AppStore>((set, get) => ({
  engagements: [],
  current: null,
  scopeEntries: [],
  error: null,

  load: async () => {
    try {
      set({ engagements: await api.list(), error: null });
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  create: async (codename) => {
    try {
      await api.create(codename);
      await get().load();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  open: async (id) => {
    try {
      const current = await api.open(id);
      set({ current, error: null });
      await get().loadScope();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  purge: async (id) => {
    try {
      await api.purge(id);
      if (get().current?.id === id) set({ current: null, scopeEntries: [] });
      await get().load();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  loadScope: async () => {
    try {
      set({ scopeEntries: await api.scopeList(), error: null });
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  // Devuelve si la entrada llegó a persistirse. En una herramienta cuya
  // propiedad de seguridad es "el alcance es exactamente el que declaraste",
  // una entrada que falla en silencio es el peor fallo disponible: el
  // operador cree que el rango está autorizado y no lo está.
  addScope: async (kind, entry) => {
    try {
      await api.scopeAdd(kind, entry);
      set({ error: null });
      await get().loadScope();
      return true;
    } catch (e) {
      set({ error: mensaje(e) });
      return false;
    }
  },

  removeScope: async (id) => {
    try {
      await api.scopeRemove(id);
      await get().loadScope();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },
}));
