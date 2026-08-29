export type LineaLog = {
  origen: "stdout" | "stderr";
  texto: string;
};

export type RunDone = {
  seq: number;
  status: string;
};

// Lo que la fase dejó ARCHIVADO en la base, no lo que el escáner vio ni
// lo que se planificó. En el camino de error llega a cero: una fase que
// falló no tiene nada que contar.
export type FaseTerminada = {
  hosts: number;
  servicios: number;
  observaciones: number;
};

// Un fallo posterior a que `run_start` haya devuelto: alcance, versión
// de la herramienta, verja... Llega por su propio evento y no como una
// línea más del log, para que la pantalla pueda enseñarlo como aviso.
export type RunError = {
  mensaje: string;
};
