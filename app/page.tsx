import CodeChecker from "@/components/code-checker";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "CodeGuardian AI · Private code checker",
  description: "Check Python, JavaScript and TypeScript in your browser. No account or repository connection. Review potential security risks, redacted findings and proposed changes.",
};

export default function Page() {
  return <CodeChecker/>;
}
