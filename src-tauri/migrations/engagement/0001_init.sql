CREATE TABLE engagement (
  id TEXT PRIMARY KEY,
  codename TEXT NOT NULL,
  authorized_by TEXT,
  authorization_ref TEXT,
  export_dir TEXT,
  created_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('draft','scoped','running','exported','purged')),
  CHECK (rowid = 1)
);

CREATE TABLE scope_entry (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('allow','deny')),
  family TEXT NOT NULL CHECK (family IN ('v4','v6')),
  cidr TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (kind, cidr)
);

CREATE TABLE tool_run (
  id INTEGER PRIMARY KEY,
  seq INTEGER NOT NULL UNIQUE,
  tool TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  tool_path TEXT NOT NULL,
  phase TEXT NOT NULL,
  argv_json TEXT NOT NULL,
  privileged INTEGER NOT NULL CHECK (privileged IN (0,1)),
  targets_json TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  exit_code INTEGER,
  status TEXT NOT NULL CHECK (status IN ('running','ok','failed','cancelled')),
  raw_path TEXT,
  raw_sha256 TEXT,
  stderr_path TEXT
);

CREATE TABLE host (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  hostname TEXT,
  mac TEXT,
  vendor TEXT,
  os_guess TEXT,
  os_accuracy INTEGER,
  state TEXT,
  first_seen_run INTEGER REFERENCES tool_run(id),
  last_seen_run  INTEGER REFERENCES tool_run(id)
);

CREATE TABLE host_tag (
  host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  PRIMARY KEY (host_id, tag)
);

CREATE TABLE service (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
  proto TEXT NOT NULL CHECK (proto IN ('tcp','udp','sctp')),
  state TEXT NOT NULL,
  service TEXT,
  product TEXT,
  version TEXT,
  extrainfo TEXT,
  tunnel TEXT,
  cpe TEXT,
  banner TEXT,
  first_seen_run INTEGER REFERENCES tool_run(id),
  last_seen_run  INTEGER REFERENCES tool_run(id),
  UNIQUE (host_id, port, proto)
);

-- Sin columna de severidad, y no por convención: aquí no existe el sitio
-- donde ponerla. La valoración la hace el consultor al redactar.
CREATE TABLE observation (
  id INTEGER PRIMARY KEY,
  tool_run_id INTEGER NOT NULL REFERENCES tool_run(id),
  host_id    INTEGER REFERENCES host(id)    ON DELETE CASCADE,
  service_id INTEGER REFERENCES service(id) ON DELETE CASCADE,
  kind      TEXT NOT NULL,
  subject   TEXT NOT NULL,
  statement TEXT NOT NULL,
  evidence     TEXT,
  evidence_ref TEXT,
  meta_json    TEXT,
  observed_at  TEXT NOT NULL,
  UNIQUE (tool_run_id, kind, subject, statement)
);

CREATE INDEX idx_service_host ON service (host_id);
CREATE INDEX idx_observation_kind ON observation (kind);
CREATE INDEX idx_observation_host ON observation (host_id);
