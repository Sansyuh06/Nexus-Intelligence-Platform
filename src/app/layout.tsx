import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "CVE-Triage-Env — Resilient AI Agent Security Triage",
  description:
    "An adversarial RL environment training AI agents to investigate CVEs under unreliable information, featuring TrueFoundry AI Gateway resilience simulation. DevNetwork [AI + ML] Hackathon 2026.",
  openGraph: {
    title: "CVE-Triage-Env — Resilient AI Security Triage",
    description:
      "Train AI agents to survive unreliable tool outputs and infrastructure chaos. Built for DevNetwork AI+ML Hackathon 2026.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} h-full antialiased dark`}
    >
      <body className="min-h-full flex flex-col" style={{ fontFamily: "var(--font-sans)" }}>
        {children}
      </body>
    </html>
  );
}
