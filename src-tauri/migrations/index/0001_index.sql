-- Registro global. Deliberadamente anémico: nada aquí puede identificar
-- a un cliente. Sin alcance, sin autorizante, sin ruta de exportación.
CREATE TABLE engagement_ref (
  id          TEXT PRIMARY KEY,
  codename    TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN
                ('draft','scoped','running','exported','purged')),
  purged_at   TEXT
);

CREATE INDEX idx_engagement_ref_state ON engagement_ref (state);
