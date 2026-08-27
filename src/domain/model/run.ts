export type LineaLog = {
  origen: "stdout" | "stderr";
  texto: string;
};

export type RunDone = {
  seq: number;
  status: string;
};
