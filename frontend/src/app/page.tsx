"use client";

import { useState } from "react";
import { Lock, Shield, Send, UserPlus, Key } from "lucide-react";

export default function Home() {
  const [status, setStatus] = useState("System Ready");
  const [keys, setKeys] = useState<{ public_key: string; private_key: string } | null>(null);

  const generateKeys = async () => {
    setStatus("Generating Keys...");
    try {
      const res = await fetch("http://localhost:3000/generate_keys");
      const data = await res.json();
      setKeys(data);
      setStatus("Keys Generated Successfully");
    } catch (e) {
      setStatus("Error: Backend Unreachable");
    }
  };

  return (
    <main className="min-h-screen p-8 max-w-4xl mx-auto space-y-12">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-slate-800 pb-6">
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-indigo-500" />
          <h1 className="text-2xl font-bold tracking-tight">InFlux</h1>
        </div>
        <div className="flex items-center space-x-2 bg-slate-900 px-3 py-1 rounded-full text-xs font-mono text-slate-400 border border-slate-800">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>{status}</span>
        </div>
      </header>

      {/* Main Content */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Left Column: Actions */}
        <section className="space-y-6">
          <div className="p-6 bg-slate-900 rounded-xl border border-slate-800 space-y-4">
            <h2 className="text-lg font-semibold flex items-center space-x-2">
              <UserPlus className="w-5 h-5 text-indigo-400" />
              <span>Identity Setup</span>
            </h2>
            <p className="text-sm text-slate-400">Initialize your cryptographic identity to begin secure communication.</p>
            <button 
              onClick={generateKeys}
              className="w-full bg-indigo-600 hover:bg-indigo-500 transition-colors py-2 rounded-lg font-medium flex items-center justify-center space-x-2"
            >
              <Key className="w-4 h-4" />
              <span>Generate E2EE Keys</span>
            </button>
          </div>

          <div className="p-6 bg-slate-900 rounded-xl border border-slate-800 space-y-4 opacity-50">
            <h2 className="text-lg font-semibold flex items-center space-x-2">
              <Lock className="w-5 h-5 text-indigo-400" />
              <span>Send Message</span>
            </h2>
            <textarea 
              disabled
              placeholder="Secure message..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 h-24"
            />
            <button disabled className="w-full bg-slate-800 py-2 rounded-lg font-medium flex items-center justify-center space-x-2">
              <Send className="w-4 h-4" />
              <span>Encrypted Send</span>
            </button>
          </div>
        </section>

        {/* Right Column: State */}
        <section className="space-y-6">
          <div className="p-6 bg-slate-900 rounded-xl border border-slate-800 h-full flex flex-col">
            <h2 className="text-lg font-semibold border-b border-slate-800 pb-4 mb-4">Cryptographic Store</h2>
            {keys ? (
              <div className="space-y-4 flex-grow font-mono text-xs">
                <div>
                  <p className="text-indigo-400 mb-1 font-sans">Public Key (Shared):</p>
                  <div className="bg-slate-950 p-2 rounded border border-slate-800 break-all h-20 overflow-y-auto">
                    {keys.public_key}
                  </div>
                </div>
                <div>
                  <p className="text-rose-400 mb-1 font-sans">Private Key (Local Only):</p>
                  <div className="bg-slate-950 p-2 rounded border border-slate-800 break-all h-20 overflow-y-auto italic">
                    {keys.private_key}
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex-grow flex items-center justify-center text-slate-500 italic text-sm text-center">
                Generate keys to view your<br/>secure identity profile.
              </div>
            )}
            <div className="mt-6 pt-4 border-t border-slate-800">
              <p className="text-[10px] text-slate-500 uppercase tracking-widest text-center">Powered by Cassandra + NATS JetStream</p>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
