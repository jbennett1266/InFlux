"use client";

import { useState, useEffect } from "react";
import { Lock, Shield, Send, UserPlus, Key, LogIn, History, LogOut } from "lucide-react";
import api from "@/lib/api";

export default function Home() {
  const [view, setView] = useState<"auth" | "dashboard">("auth");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("Idle");
  const [keys, setKeys] = useState<{ public_key: string; private_key: string } | null>(null);
  const [messages, setMessages] = useState<any[]>([]);

  useEffect(() => {
    if (localStorage.getItem("access_token")) {
      setView("dashboard");
      fetchMessages();
    }
  }, []);

  const handleAuth = async () => {
    setStatus("Authenticating...");
    try {
      if (authMode === "register") {
        await api.post("/register", { username, password });
        setAuthMode("login");
        setStatus("Registration Successful. Please Login.");
      } else {
        const res = await api.post("/login", { username, password });
        localStorage.setItem("access_token", res.data.access_token);
        localStorage.setItem("refresh_token", res.data.refresh_token);
        setView("dashboard");
        fetchMessages();
        setStatus("Logged In");
      }
    } catch (e: any) {
      setStatus(`Error: ${e.response?.status || "Server Offline"}`);
    }
  };

  const fetchMessages = async () => {
    try {
      const res = await api.get("/messages");
      setMessages(res.data);
    } catch (e) {}
  };

  const generateKeys = async () => {
    setStatus("Generating Keys...");
    try {
      const res = await api.get("/generate_keys");
      setKeys(res.data);
      setStatus("Keys Generated (Local)");
    } catch (e) {
      setStatus("Error fetching keys");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    setView("auth");
  };

  if (view === "auth") {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-slate-950 text-slate-50">
        <div className="w-full max-w-md p-8 bg-slate-900 rounded-2xl border border-slate-800 space-y-8 shadow-2xl">
          <div className="text-center space-y-2">
            <Shield className="w-12 h-12 text-indigo-500 mx-auto" />
            <h1 className="text-3xl font-bold tracking-tight">InFlux</h1>
            <p className="text-slate-400 text-sm">{authMode === "login" ? "Welcome back" : "Create your secure account"}</p>
          </div>

          <div className="space-y-4">
            <input 
              type="text" 
              placeholder="Username" 
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm focus:ring-1 focus:ring-indigo-500 outline-none"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input 
              type="password" 
              placeholder="Password" 
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm focus:ring-1 focus:ring-indigo-500 outline-none"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button 
              onClick={handleAuth}
              className="w-full bg-indigo-600 hover:bg-indigo-500 py-3 rounded-lg font-bold flex items-center justify-center space-x-2 transition-all active:scale-[0.98]"
            >
              {authMode === "login" ? <LogIn className="w-4 h-4" /> : <UserPlus className="w-4 h-4" />}
              <span>{authMode === "login" ? "Login" : "Register"}</span>
            </button>
            
            <button 
              onClick={() => setAuthMode(authMode === "login" ? "register" : "login")}
              className="w-full text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              {authMode === "login" ? "Need an account? Register" : "Have an account? Login"}
            </button>
          </div>
          <p className="text-[10px] text-center text-slate-600 font-mono uppercase tracking-widest">{status}</p>
        </div>
      </div>
    );
  }

  return (
    <main className="min-h-screen p-8 max-w-6xl mx-auto space-y-12 bg-slate-950 text-slate-50">
      <header className="flex items-center justify-between border-b border-slate-800 pb-6">
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-indigo-500" />
          <h1 className="text-2xl font-bold tracking-tight">InFlux</h1>
        </div>
        <div className="flex items-center space-x-4">
            <span className="text-xs font-mono text-slate-400">@{username}</span>
            <button onClick={handleLogout} className="p-2 hover:bg-slate-900 rounded-lg text-rose-400 transition-colors">
                <LogOut className="w-4 h-4" />
            </button>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Identity & Keys */}
        <section className="space-y-6">
          <div className="p-6 bg-slate-900 rounded-xl border border-slate-800 space-y-4">
            <h2 className="text-lg font-semibold flex items-center space-x-2">
              <Key className="w-5 h-5 text-indigo-400" />
              <span>Identity Profile</span>
            </h2>
            <button 
              onClick={generateKeys}
              className="w-full bg-indigo-600 hover:bg-indigo-500 transition-colors py-2 rounded-lg font-medium text-sm flex items-center justify-center space-x-2"
            >
              <Key className="w-4 h-4" />
              <span>Generate New Keys</span>
            </button>

            {keys && (
              <div className="pt-4 space-y-3 font-mono text-[10px]">
                <div className="p-2 bg-slate-950 rounded border border-slate-800">
                    <p className="text-indigo-400 mb-1">Public Key</p>
                    <p className="break-all text-slate-500">{keys.public_key}</p>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Message Feed */}
        <section className="lg:col-span-2 space-y-6">
           <div className="p-6 bg-slate-900 rounded-xl border border-slate-800 flex flex-col h-[500px]">
            <h2 className="text-lg font-semibold border-b border-slate-800 pb-4 mb-4 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                    <History className="w-5 h-5 text-indigo-400" />
                    <span>Secure Channel: #global</span>
                </div>
                <button onClick={fetchMessages} className="text-xs text-indigo-500 hover:underline">Refresh</button>
            </h2>
            
            <div className="flex-grow overflow-y-auto space-y-4 pr-2 custom-scrollbar">
                {messages.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-slate-600 text-sm italic">
                        No messages in history
                    </div>
                ) : (
                    messages.map((m) => (
                        <div key={m.id} className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                            <div className="flex items-center justify-between text-[10px] text-slate-500">
                                <span className="font-bold text-indigo-500">@{m.sender}</span>
                                <span>{new Date(m.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <p className="text-sm text-slate-300 break-words">{m.content}</p>
                        </div>
                    ))
                )}
            </div>

            <div className="mt-6 flex space-x-2">
                <input 
                    type="text" 
                    placeholder="Type a secure message..."
                    className="flex-grow bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm outline-none focus:ring-1 focus:ring-indigo-500"
                    onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                            const input = e.target as HTMLInputElement;
                            api.post("/publish", { content: input.value });
                            input.value = "";
                            setTimeout(fetchMessages, 500);
                        }
                    }}
                />
                <button className="bg-indigo-600 p-2 rounded-lg hover:bg-indigo-500 transition-colors">
                    <Send className="w-5 h-5" />
                </button>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
