import { invoke } from "@tauri-apps/api/core";

// Sin `privileged` aquí a propósito: el comando calcula el privilegio
// real él mismo (`preflight::running_privileged()`). Aceptarlo como
// argumento reabriría, con el frontend, el hueco que la verja cerró
// para los adaptadores -- cualquiera que invocase el comando podría
// declararse privilegiado sin que el proceso lo esté de verdad.
export const api = {
  // El argv REAL que lanzaría la fase, una cadena por invocación. Solo
  // el backend lo sabe: sale del mismo `planificar` que usa la
  // ejecución, ya con el alcance validado y el adaptador consultado.
  //
  // `elevar` es una PETICIÓN de elevación, nunca una prueba de
  // privilegio: el backend la verifica él mismo antes de construir
  // las banderas privilegiadas. Tiene que ser el mismo valor que el
  // que se pase a `start` para la misma fase -- si `preview` y
  // `start` vieran valores distintos, el diálogo de confirmación
  // enseñaría un argv que no es el que de verdad se lanza.
  preview: (phase: string, toolId: string, targets: string[], elevar: boolean): Promise<string[]> =>
    invoke("run_preview", { phase, toolId, targets, elevar }),
  start: (phase: string, toolId: string, targets: string[], elevar: boolean): Promise<void> =>
    invoke("run_start", { phase, toolId, targets, elevar }),
  cancel: (): Promise<void> => invoke("run_cancel"),
};
