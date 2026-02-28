import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "InFlux | Secure Messaging",
  description: "End-to-end encrypted messaging powered by Cassandra and NATS",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-50 antialiased">{children}</body>
    </html>
  );
}
