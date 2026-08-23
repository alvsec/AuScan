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

// Se acumulan TODAS las divergencias antes de fallar. Abortar en la primera
// es lo que dejó escondidas dos durante una revisión entera.
describe("espejo del guard", () => {
  it("coincide con el corpus en todos los casos", () => {
    const fallos: string[] = [];
    for (const caso of corpus.cases) {
      const spec = corpus.scopes[caso.scope];
      if (!spec) {
        fallos.push(`scope ${caso.scope} no está en el corpus`);
        continue;
      }
      const real = inScope(spec, caso.target);
      if (real !== caso.expect) {
        fallos.push(
          `${caso.scope} · ${JSON.stringify(caso.target)}: espejo=${real} corpus=${caso.expect}`,
        );
      }
    }
    expect(fallos.join("\n") || "sin divergencias").toBe("sin divergencias");
  });

  it("coincide con el corpus al parsear entradas", () => {
    const fallos: string[] = [];
    for (const e of corpus.entries) {
      const r = parseEntry(e.input);
      const real = "net" in r ? "ok" : r.error;
      if (real !== e.expect) {
        fallos.push(`${JSON.stringify(e.input)}: espejo=${real} corpus=${e.expect}`);
      }
    }
    expect(fallos.join("\n") || "sin divergencias").toBe("sin divergencias");
  });
});
