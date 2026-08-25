export type ToolStatus =
  | { kind: "ok"; path: string; version: string }
  | { kind: "tooOld"; path: string; version: string; minimum: string }
  | { kind: "missing" }
  | { kind: "unparseable"; path: string; raw: string };

export type ToolReport = {
  toolId: string;
  status: ToolStatus;
  installCommand: string;
};

export type FileVaultStatus = "on" | "off" | "unknown";

export type PreflightReport = {
  tools: ToolReport[];
  privileged: boolean;
  filevault: FileVaultStatus;
};
