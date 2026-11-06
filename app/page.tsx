import Workspace from "@/components/workspace";

export default function Page() {
  return <Workspace backendConfigured={Boolean(process.env.API_URL)}/>;
}
