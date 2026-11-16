import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { 
  title: "CyberHuntLab · Plataforma de Segurança com IA", 
  description: "CyberHuntLab — laboratório de segurança de aplicações, análise de projetos ZIP, Kubernetes, Docker, Cloud e inteligência artificial." 
};
export default function RootLayout({ children }: Readonly<{children: React.ReactNode}>) {
  return <html lang="pt-BR"><body>{children}</body></html>;
}
