export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Finding = {
  fingerprint: string; path: string; line: number; end_line: number; rule_id: string;
  title: string; message: string; severity: Severity; confidence: string; cwe: string;
  owasp: string; engine: string; classification: string; snippet: string; status: string;
  review_note?: string; category?: "sast" | "secret" | "dependency" | "configuration";
  references?: string[]; advisory_ids?: string[]; package?: string; fixed_version?: string;
  first_seen?: string; last_seen?: string;
};
export type Coverage = {files: number; languages: string[]; engines: {name: string; status: string}[]; complete: boolean; errors: string[]; rule_version: string};
export type Scan = {
  id: string; repository_id: string; commit_sha: string; branch: string; status: string;
  created_at: string; completed_at?: string; findings: Finding[]; files: Record<string, string>;
  summary: Record<Severity, number>; coverage: Coverage; error?: string; comparison?: Comparison;
  trigger?: string; attempts?: number; changed_files?: string[]; repository?: Repository;
};
export type Repository = {
  id: string; full_name: string; branch: string; scans?: Scan[]; github_id?: number;
  installation_id?: number; visibility?: string; language?: string; connection_status?: string;
  synced_at?: string; github_updated_at?: string; auto_scan?: boolean; schedule_hours?: number;
  checks_enabled?: boolean; blocking_checks?: boolean;
};
export type Comparison = {new: string[]; resolved: string[]; unchanged: string[]; baseline_commit: string; reliable: boolean};
export type Explanation = {provider: string; explanation: string; conditions_to_verify: string[]; remediation: string; tests: string[]; citations: {id: string; title: string; url: string; guidance: string}[]; limitations: string; model?: string; impact?: string; safer_code_example?: {code:string;caveat:string}; false_positive_considerations?: string[]};
export type Patch = {path: string; original: string; modified: string; diff: string; digest: string; caveat: string; requires_human_review: boolean; tested: boolean; origin: string};
export type Identity = {login: string; csrf_token: string; avatar_url?: string};
export type Capabilities = {github: boolean; llm: boolean; checks: boolean; repository_writes: boolean; scanner_mode: string; install_url?: string};
export type GitRepository = {id: number; full_name: string; private: boolean; branch: string; language?: string; updated_at?: string; installation_id: number};
export type Installation = {id: string; github_id: number; account: string; account_type: string; status: string; synced_at?: string; permissions?: Record<string,string>};
export type Preferences = {notify_scan_failure: boolean; notify_high_findings: boolean};
export type Notification = {id: string; scan_id: string; message: string; read: boolean; created_at: string};
export type Dashboard = {
  repositories: number; scanned_repositories: number; open_findings: number;
  by_severity: Record<Severity, number>; vulnerable_dependencies: number; potential_secrets: number;
  resolved_findings: number; scan_success_rate: number | null; scan_failure_rate: number | null;
  recent_scans: (Scan & {repository_name:string})[]; trend: {date:string; findings:number}[]; notifications_unread:number;
};
export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
export const classificationLabel = (f: Finding) => f.classification === "verified_analyzer" ? "Analyzer evidence" : "Potential vulnerability";
export const activeScanStates = new Set(["queued", "preparing", "scanning", "analyzing"]);
