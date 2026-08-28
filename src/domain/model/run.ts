export type LineaLog = {
  origen: "stdout" | "stderr";
  texto: string;
};

export type RunDone = {
  seq: number;
  status: string;
};

// Un fallo posterior a que `run_start` haya devuelto: alcance, versión
// de la herramienta, verja... Llega por su propio evento y no como una
// línea más del log, para que la pantalla pueda enseñarlo como aviso.
export type RunError = {
  mensaje: string;
};
