import { readFile } from "node:fs/promises";
import path from "node:path";
import Workspace from "@/components/workspace";
import type { Demo } from "@/lib/types";

export default async function Page() {
  const data: Demo = JSON.parse(await readFile(path.join(process.cwd(), "public/demo.json"), "utf8"));
  return <Workspace initial={data} backendConfigured={Boolean(process.env.API_URL)}/>;
}
