import Workspace from "@/components/workspace";
import { connection } from "next/server";

export default async function Page() {
  // Runtime configuration must not be frozen into a statically generated page.
  await connection();
  return <Workspace backendConfigured={Boolean(process.env.API_URL)}/>;
}
