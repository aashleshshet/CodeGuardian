import type { Metadata } from "next";
import "@fontsource/public-sans/400.css";
import "@fontsource/public-sans/500.css";
import "@fontsource/public-sans/600.css";
import "@fontsource/public-sans/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "./globals.css";

export const metadata: Metadata = {title: "CodeGuardian AI · Secure code review", description: "Follow the evidence. Review real static analysis findings, understand security risks, and inspect secure code changes before they ship."};
export default function RootLayout({children}: {children: React.ReactNode}) {
  return <html lang="en" suppressHydrationWarning><body><script dangerouslySetInnerHTML={{__html: `try{document.documentElement.dataset.theme=localStorage.getItem('cg-theme')||'dark'}catch{}`}}/>{children}</body></html>;
}
