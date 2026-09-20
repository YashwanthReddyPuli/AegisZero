import './globals.css';
import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AegisZero - Security Operations Center',
  description: 'Real-Time AI-Powered Application Security & ML Payload Scanner',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-white min-h-screen antialiased selection:bg-cyan-500 selection:text-black">
        {children}
      </body>
    </html>
  );
}
