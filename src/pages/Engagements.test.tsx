import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import "../i18n";
import { useAppStore } from "../store/useAppStore";
import { Engagements } from "./Engagements";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

const UNO = {
  id: "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b",
  codename: "CLAVEL",
  createdAt: "2026-08-22T10:00:00Z",
  state: "draft" as const,
  purgedAt: null,
};

describe("Engagements", () => {
  beforeEach(() => {
    invoke.mockReset();
    useAppStore.setState({ engagements: [], current: null, error: null });
  });

  it("muestra los engagements existentes", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "engagement_list" ? Promise.resolve([UNO]) : Promise.resolve(null),
    );

    render(<Engagements />);
    expect(await screen.findByText("CLAVEL")).toBeInTheDocument();
  });

  it("crea un engagement con el nombre en clave escrito", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "engagement_list" ? Promise.resolve([]) : Promise.resolve(UNO),
    );

    render(<Engagements />);
    await userEvent.type(await screen.findByLabelText(/nombre en clave/i), "ROMERO");
    await userEvent.click(screen.getByRole("button", { name: /crear/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("engagement_create", { codename: "ROMERO" });
    });
  });

  it("pide confirmación antes de purgar y avisa de que la exportación no se toca", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "engagement_list" ? Promise.resolve([UNO]) : Promise.resolve(null),
    );

    render(<Engagements />);
    await userEvent.click(await screen.findByRole("button", { name: /^purgar$/i }));

    expect(screen.getByRole("dialog")).toHaveTextContent(
      /carpeta de exportación NO se toca/i,
    );
    expect(invoke).not.toHaveBeenCalledWith("engagement_purge", expect.anything());
  });

  it("no purga si se cancela la confirmación", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "engagement_list" ? Promise.resolve([UNO]) : Promise.resolve(null),
    );

    render(<Engagements />);
    await userEvent.click(await screen.findByRole("button", { name: /^purgar$/i }));
    await userEvent.click(screen.getByRole("button", { name: /cancelar/i }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(invoke).not.toHaveBeenCalledWith("engagement_purge", expect.anything());
  });
});
