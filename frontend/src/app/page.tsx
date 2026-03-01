"use client";

import { useState, useEffect } from "react";
import { Lock, Shield, Send, UserPlus, Key, LogIn, History, LogOut, MessageSquare, Plus, Users, Hash, X } from "lucide-react";
import api from "@/lib/api";

export default function Home() {
  const [view, setView] = useState<"auth" | "dashboard">("auth");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("Idle");
  
  const [threads, setThreads] = useState<any[]>([]);
  const [activeThread, setActiveThread] = useState<any>({ id: "global", name: "Global Channel", is_group: true });
  const [messages, setMessages] = useState<any[]>([]);
  const [keys, setKeys] = useState<{ public_key: string; private_key: string } | null>(null);

  // UI States
  const [showThreadModal, setShowThreadModal] = useState(false);
  const [modalIsGroup, setModalIsGroup] = useState(false);
  const [newThreadName, setNewThreadName] = useState("");
  const [newThreadMembers, setNewThreadMembers] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [messageInput, setMessageInput] = useState("");

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem("access_token") : null;
    const storedUser = typeof window !== 'undefined' ? localStorage.getItem("username") : null;
    if (token && storedUser) {
      setUsername(storedUser);
      setView("dashboard");
      loadDashboardData(storedUser);
    }
  }, []);

  const loadDashboardData = async (user: string) => {
    fetchThreads();
    fetchMessages("global");
  };

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
        localStorage.setItem("username", username);
        setView("dashboard");
        loadDashboardData(username);
        setStatus("Logged In");
      }
    } catch (e: any) {
      setStatus(`Error: ${e.response?.status || "Server Offline"}`);
    }
  };

  const fetchThreads = async () => {
    try {
      const res = await api.get(`/threads`);
      setThreads(res.data);
    } catch (e) {}
  };

  const fetchMessages = async (channelId: string) => {
    try {
      const res = await api.get(`/messages/${channelId}`);
      setMessages(res.data);
    } catch (e) {}
  };

  const handleCreateThread = async () => {
    if (!newThreadName) return;
    
    try {
      const members = newThreadMembers.split(',').map(m => m.trim()).filter(m => m !== "");
      await api.post("/threads", {
        name: modalIsGroup ? newThreadName : `@${newThreadName}`,
        members: modalIsGroup ? members : [newThreadName],
        is_group: modalIsGroup
      });
      setShowThreadModal(false);
      setNewThreadName("");
      setNewThreadMembers("");
      fetchThreads();
    } catch (e) {}
  };

  const sendMessage = async () => {
    if (!messageInput.trim() || isSending) return;
    
    setIsSending(true);
    const content = messageInput;
    setMessageInput(""); // Optimistic clear

    try {
      await api.post(`/publish/${activeThread.id}`, { content });
      await fetchMessages(activeThread.id);
    } catch (e) {
      setMessageInput(content); // Revert on failure
    } finally {
      setIsSending(false);
    }
  };

  const handleLogout = () => {
    localStorage.clear();
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
    <div className="flex h-screen bg-slate-950 text-slate-50 overflow-hidden font-sans">
      {/* Thread Creation Modal */}
      {showThreadModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-md rounded-2xl shadow-2xl overflow-hidden">
            <div className="p-6 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xl font-bold">{modalIsGroup ? "Create New Group" : "Direct Message"}</h3>
              <button onClick={() => setShowThreadModal(false)} className="text-slate-500 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">{modalIsGroup ? "Group Name" : "Recipient Username"}</label>
                <input 
                  autoFocus
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:ring-1 focus:ring-indigo-500 outline-none"
                  placeholder={modalIsGroup ? "Team Alpha" : "alice_crypto"}
                  value={newThreadName}
                  onChange={e => setNewThreadName(e.target.value)}
                />
              </div>
              {modalIsGroup && (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Members (comma separated)</label>
                  <input 
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:ring-1 focus:ring-indigo-500 outline-none"
                    placeholder="bob, charlie, dave"
                    value={newThreadMembers}
                    onChange={e => setNewThreadMembers(e.target.value)}
                  />
                </div>
              )}
              <button 
                onClick={handleCreateThread}
                className="w-full bg-indigo-600 hover:bg-indigo-500 py-3 rounded-xl font-bold flex items-center justify-center space-x-2 transition-all active:scale-[0.98]"
              >
                <Plus className="w-4 h-4" />
                <span>Initialize {modalIsGroup ? "Group" : "Thread"}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800 bg-slate-900 flex flex-col">
        <div className="p-6 border-b border-slate-800 flex items-center space-x-3">
          <Shield className="w-6 h-6 text-indigo-500" />
          <span className="font-bold tracking-tight text-lg">InFlux</span>
        </div>
        
        <nav className="flex-grow overflow-y-auto p-4 space-y-8">
          <div>
            <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-4 px-2">Public</h3>
            <button 
                onClick={() => { setActiveThread({ id: "global", name: "Global Channel" }); fetchMessages("global"); }}
                className={`w-full flex items-center space-x-3 px-2 py-2 rounded-lg transition-colors ${activeThread.id === 'global' ? 'bg-indigo-600 text-white' : 'hover:bg-slate-800 text-slate-400'}`}
            >
              <Hash className="w-4 h-4" />
              <span className="text-sm font-medium">global</span>
            </button>
          </div>

          <div>
            <div className="flex items-center justify-between mb-4 px-2">
                <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Secure Threads</h3>
                <button onClick={() => { setModalIsGroup(false); setShowThreadModal(true); }} className="text-indigo-400 hover:text-indigo-300 transition-colors"><Plus className="w-4 h-4" /></button>
            </div>
            <div className="space-y-1">
                {threads.filter(t => !t.is_group).map(t => (
                    <button 
                        key={t.id}
                        onClick={() => { setActiveThread(t); fetchMessages(t.id); }}
                        className={`w-full flex items-center space-x-3 px-2 py-2 rounded-lg transition-colors ${activeThread.id === t.id ? 'bg-slate-800 text-white border border-slate-700' : 'hover:bg-slate-800/50 text-slate-400'}`}
                    >
                        <div className="w-2 h-2 rounded-full bg-emerald-500" />
                        <span className="text-sm truncate">{t.name}</span>
                    </button>
                ))}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-4 px-2">
                <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Encrypted Groups</h3>
                <button onClick={() => { setModalIsGroup(true); setShowThreadModal(true); }} className="text-indigo-400 hover:text-indigo-300 transition-colors"><Plus className="w-4 h-4" /></button>
            </div>
            <div className="space-y-1">
                {threads.filter(t => t.is_group).map(t => (
                    <button 
                        key={t.id}
                        onClick={() => { setActiveThread(t); fetchMessages(t.id); }}
                        className={`w-full flex items-center space-x-3 px-2 py-2 rounded-lg transition-colors ${activeThread.id === t.id ? 'bg-indigo-600 text-white' : 'hover:bg-slate-800 text-slate-400'}`}
                    >
                        <Users className="w-4 h-4" />
                        <span className="text-sm truncate">{t.name}</span>
                    </button>
                ))}
            </div>
          </div>
        </nav>

        <div className="p-4 border-t border-slate-800 bg-slate-950/50">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                    <div className="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center font-bold text-xs uppercase">
                        {username.slice(0, 2)}
                    </div>
                    <span className="text-xs font-mono text-slate-400">@{username}</span>
                </div>
                <button onClick={handleLogout} className="p-2 hover:bg-slate-800 rounded-lg text-rose-400 transition-colors">
                    <LogOut className="w-4 h-4" />
                </button>
            </div>
        </div>
      </aside>

      {/* Main Chat Area */}
      <main className="flex-grow flex flex-col">
        <header className="h-16 border-b border-slate-800 flex items-center justify-between px-8 bg-slate-950">
            <div className="flex items-center space-x-3">
                <MessageSquare className="w-5 h-5 text-indigo-400" />
                <h2 className="font-bold text-lg">{activeThread.name}</h2>
            </div>
            <div className="flex items-center space-x-2 bg-slate-900 px-3 py-1 rounded-full text-[10px] font-mono text-slate-400 border border-slate-800">
                <Lock className="w-3 h-3 text-emerald-500" />
                <span>End-to-End Encrypted</span>
            </div>
        </header>

        <div className="flex-grow overflow-y-auto p-8 space-y-6 custom-scrollbar bg-[url('/grid.svg')] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))]">
            {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center space-y-4 opacity-20">
                    <Shield className="w-16 h-16" />
                    <p className="text-sm font-medium tracking-widest uppercase">Start of secure history</p>
                </div>
            ) : (
                messages.map((m) => (
                    <div key={m.id} className={`flex flex-col ${m.sender === username ? 'items-end' : 'items-start'}`}>
                        <div className={`max-w-md p-4 rounded-2xl border ${m.sender === username ? 'bg-indigo-600 border-indigo-500' : 'bg-slate-900 border-slate-800'}`}>
                            <div className="flex items-center justify-between mb-1 space-x-8">
                                <span className="text-[10px] font-bold opacity-50 uppercase tracking-tighter">@{m.sender}</span>
                                <span className="text-[10px] opacity-30 italic">{new Date(m.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <p className="text-sm leading-relaxed">{m.content}</p>
                        </div>
                    </div>
                ))
            )}
        </div>

        <footer className="p-6 bg-slate-950 border-t border-slate-800">
            <div className="max-w-4xl mx-auto flex space-x-3">
                <input 
                    type="text" 
                    placeholder={`Message ${activeThread.name}...`}
                    className="flex-grow bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm outline-none focus:ring-1 focus:ring-indigo-500 transition-all shadow-inner disabled:opacity-50"
                    value={messageInput}
                    disabled={isSending}
                    onChange={e => setMessageInput(e.target.value)}
                    onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                            sendMessage();
                        }
                    }}
                />
                <button 
                  onClick={sendMessage}
                  disabled={isSending || !messageInput.trim()}
                  className="bg-indigo-600 p-3 rounded-xl hover:bg-indigo-500 transition-all active:scale-95 shadow-lg shadow-indigo-500/20 disabled:bg-slate-800 disabled:opacity-50"
                >
                    <Send className={`w-5 h-5 ${isSending ? 'animate-pulse' : ''}`} />
                </button>
            </div>
        </footer>
      </main>
    </div>
  );
}
