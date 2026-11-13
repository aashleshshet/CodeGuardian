/** Explicit OWASP Top 10:2021 mappings; unmapped weaknesses stay unmapped. */
export function owaspCategory(cwe: string): string {
  const id = Number(cwe.replace("CWE-", ""));
  if ([78, 79, 89, 94, 95, 1336].includes(id)) return "A03:2021 · Injection";
  if ([22, 601].includes(id)) return "A01:2021 · Broken Access Control";
  if ([327, 328].includes(id)) return "A02:2021 · Cryptographic Failures";
  if ([295, 798].includes(id)) return "A07:2021 · Identification and Authentication Failures";
  if (id === 502) return "A08:2021 · Software and Data Integrity Failures";
  if (id === 918) return "A10:2021 · Server-Side Request Forgery";
  return "Unmapped";
}
