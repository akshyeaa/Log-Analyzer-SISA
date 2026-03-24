// import { Geist, Geist_Mono } from "next/font/google";
import { Inter } from "next/font/google";
import { JetBrains_Mono } from "next/font/google";

const jetbrainsMono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
});

export const metadata = {
  title: "AI Secure Data Intelligence Platform",
  description: "Analyze logs, detect risks, and generate AI insights",
  icons: {
    icon: "/favicon.png",
  },
};

export default function RootLayout({ children }) {
  return (
    <html
      lang="en"
      className={`${inter.className} h-full antialiased`}
    >
      <body className={`${jetbrainsMono.className} relative min-h-screen bg-neutral-900 text-white overflow-x-hidden`}>

        
        <div className="absolute bottom-0 left-0 right-0 top-0 bg-[radial-gradient(circle_500px_at_50%_200px,#3e3e3e,transparent)"></div>

        {/* Content */}
        <div className="relative z-10">
          {children}
        </div>

      </body>
    </html>
  );
}




