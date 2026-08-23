import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { inScope, parseEntry, type ScopeSpec, type Verdict } from "./inScope";

type Corpus = {
  scopes: Record<string, ScopeSpec>;
  cases: { scope: string; target: string; expect: Verdict }[];
  entries: { input: string; expect: "ok" | "ambiguous" | "overbroad" | "invalid" }[];
};

const corpus: Corpus = JSON.parse(
  readFileSync("fixtures/scope/corpus.json", "utf8"),
) as Corpus;

describe("espejo del guard", () => {
  it("coincide con el corpus en todos los casos", () => {
    for (const caso of corpus.cases) {
      const spec = corpus.scopes[caso.scope];
      expect(spec, `scope ${caso.scope} no está en el corpus`).toBeDefined();
      expect(
        inScope(spec!, caso.target),
        `scope ${caso.scope} · objetivo ${JSON.stringify(caso.target)}`,
      ).toBe(caso.expect);
    }
  });

  it("coincide con el corpus al parsear entradas", () => {
    for (const e of corpus.entries) {
      const r = parseEntry(e.input);
      const real = "net" in r ? "ok" : r.error;
      expect(real, `entrada ${JSON.stringify(e.input)}`).toBe(e.expect);
    }
  });
});
