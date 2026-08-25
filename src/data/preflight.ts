import { invoke } from "@tauri-apps/api/core";

import type { PreflightReport } from "../domain/model/preflight";

export const preflightApi = {
  run: () => invoke<PreflightReport>("preflight_run"),
  install: (toolId: string) => invoke<string>("preflight_install", { toolId }),
};
