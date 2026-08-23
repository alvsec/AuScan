import { invoke } from "@tauri-apps/api/core";

import type { EngagementRef, ScopeEntry, ScopeKind } from "../domain/model/types";

/// Envoltorio tipado sobre invoke. El frontend nunca ve SQL: la base la
/// posee Rust, que es también quien aplica el guard de alcance.
export const api = {
  list: () => invoke<EngagementRef[]>("engagement_list"),
  create: (codename: string) =>
    invoke<EngagementRef>("engagement_create", { codename }),
  open: (id: string) => invoke<EngagementRef>("engagement_open", { id }),
  purge: (id: string) => invoke<EngagementRef>("engagement_purge", { id }),
  scopeList: () => invoke<ScopeEntry[]>("scope_list"),
  scopeAdd: (kind: ScopeKind, entry: string, note?: string) =>
    invoke<ScopeEntry>("scope_add", { kind, entry, note: note ?? null }),
  scopeRemove: (id: number) => invoke<void>("scope_remove", { id }),
  scopeCheck: (target: string) => invoke<string[]>("scope_check", { target }),
};
