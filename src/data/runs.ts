import { invoke } from "@tauri-apps/api/core";

// Sin `privileged` aquí a propósito: el comando calcula el privilegio
// real él mismo (`preflight::running_privileged()`). Aceptarlo como
// argumento reabriría, con el frontend, el hueco que la verja cerró
// para los adaptadores -- cualquiera que invocase el comando podría
// declararse privilegiado sin que el proceso lo esté de verdad.
export const api = {
  start: (phase: string, toolId: string, targets: string[]): Promise<void> =>
    invoke("run_start", { phase, toolId, targets }),
  cancel: (): Promise<void> => invoke("run_cancel"),
};
