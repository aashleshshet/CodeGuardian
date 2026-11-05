// INTENTIONALLY VULNERABLE FIXTURE. Never start this service.
import { exec } from 'node:child_process';

type Request = { query: { customerId: string; report: string } };
type Database = { query: (sql: string) => Promise<unknown[]> };

export async function getPayments(req: Request, database: Database) {
  const customerId = req.query.customerId;
  const query = `SELECT * FROM payments WHERE customer_id = '${customerId}'`;
  return database.query(query);
}

export function exportReport(req: Request) {
  const report = req.query.report;
  exec(`generate-report --name ${report}`);
}
