/** Analyzer evidence contains labels and locations, never copied source values. */
export type FlowStep = {line: number; kind: "source" | "assignment" | "call" | "sink"; label: string};
export type StructuralFinding = {
  ruleId: string;
  title: string;
  severity: "high" | "medium" | "low";
  cwe: string;
  line: number;
  endLine: number;
  message: string;
  remediation: string;
  conditions: string[];
  classification: "potential_vulnerability" | "secure_coding_suggestion";
  evidence: "data_flow" | "structural";
  trace?: FlowStep[];
  /** Optional precise innerHTML property span for a review-only textContent patch. */
  patchProperty?: {start: number; end: number};
};
export type StructuralResult = {
  findings: StructuralFinding[];
  parsed: boolean;
  /** Diagnostic messages must never echo source, string values or identifiers. */
  diagnostics: {line: number; message: string}[];
  truncated: boolean;
};
