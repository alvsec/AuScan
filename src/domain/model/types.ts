export type EngagementState =
  | "draft"
  | "scoped"
  | "running"
  | "exported"
  | "purged";

export type EngagementRef = {
  id: string;
  codename: string;
  createdAt: string;
  state: EngagementState;
  purgedAt: string | null;
};

export type ScopeKind = "allow" | "deny";

export type ScopeEntry = {
  id: number;
  kind: ScopeKind;
  family: "v4" | "v6";
  cidr: string;
  note: string | null;
  createdAt: string;
};
