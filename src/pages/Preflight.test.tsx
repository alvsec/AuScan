import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import "../i18n";
import { Preflight } from "./Preflight";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

const INFORME_CON_HERRAMIENTA_FALTANTE = {
  tools: [
    {
      toolId: "fake",
      status: { kind: "missing" },
      installCommand: "brew install fake-tool",
    },
  ],
  privileged: false,
  filevault: "on",
};

describe("Preflight", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("muestra el estado de cada herramienta al montar", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "preflight_run"
        ? Promise.resolve({
            tools: [
              { toolId: "fake", status: { kind: "ok", path: "/bin/fake", version: "2.3.0" }, installCommand: "brew install fake-tool" },
            ],
            privileged: false,
            filevault: "on",
          })
        : Promise.resolve(null),
    );

    render(<Preflight />);

    expect(await screen.findByText("fake")).toBeInTheDocument();
    expect(screen.getByText(/instalada/i)).toBeInTheDocument();
  });

  it("dice cuando el alcance está vacío de herramientas", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "preflight_run"
        ? Promise.resolve({ tools: [], privileged: false, filevault: "unknown" })
        : Promise.resolve(null),
    );

    render(<Preflight />);
    expect(await screen.findByText(/todavía no hay ninguna herramienta/i)).toBeInTheDocument();
  });

  it("pide confirmación antes de ejecutar el comando de instalación", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "preflight_run"
        ? Promise.resolve(INFORME_CON_HERRAMIENTA_FALTANTE)
        : Promise.resolve("instalado"),
    );

    render(<Preflight />);
    await userEvent.click(await screen.findByRole("button", { name: /^instalar$/i }));

    expect(screen.getByRole("dialog")).toHaveTextContent(/brew install fake-tool/);
    expect(invoke).not.toHaveBeenCalledWith("preflight_install", expect.anything());

    await userEvent.click(screen.getByRole("button", { name: /^ejecutar$/i }));
    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("preflight_install", { toolId: "fake" });
    });
  });
});
