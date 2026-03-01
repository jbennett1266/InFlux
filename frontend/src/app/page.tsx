"use client";

import { useState, useEffect } from "react";
import { Lock, Shield, Send, UserPlus, Key, LogIn, History, LogOut, MessageSquare, Plus, Users, Hash, X, ShieldAlert, UserMinus, Crown, Sun, Moon } from "lucide-react";
import api from "@/lib/api";

export default function Home() {
  const [view, setView] = useState<"auth" | "dashboard">("auth");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("Idle");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  
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
  const [showAdminModal, setShowAdminModal] = useState(false);
  const [adminTargetUser, setAdminTargetUser] = useState("");

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem("access_token") : null;
    const storedUser = typeof window !== 'undefined' ? localStorage.getItem("username") : null;
    const storedTheme = typeof window !== 'undefined' ? localStorage.getItem("theme") as "dark" | "light" : "dark";
    
    setTheme(storedTheme || "dark");
    if (storedTheme === "light") document.documentElement.classList.remove("dark");
    else document.documentElement.classList.add("dark");

    if (token && storedUser) {
      setUsername(storedUser);
      setView("dashboard");
      loadDashboardData(storedUser);
    }
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === "dark" ? "light" : "dark";
    setTheme(newTheme);
    localStorage.setItem("theme", newTheme);
    if (newTheme === "light") document.documentElement.classList.remove("dark");
    else document.documentElement.classList.add("dark");
  };

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
    setMessageInput(""); 
    try {
      await api.post(`/publish/${activeThread.id}`, { content });
      await fetchMessages(activeThread.id);
    } catch (e) {
      setMessageInput(content); 
    } finally {
      setIsSending(false);
    }
  };

  const handleAddMember = async () => {
    if (!adminTargetUser) return;
    try {
      await api.post(`/threads/${activeThread.id}/members`, { username: adminTargetUser });
      setAdminTargetUser("");
      setStatus("Member Added");
    } catch (e) { setStatus("Admin Error"); }
  };

  const handleRemoveMember = async (target: string) => {
    try {
      await api.delete(`/threads/${activeThread.id}/members/${target}`);
      setStatus("Member Removed");
    } catch (e) { setStatus("Admin Error"); }
  };

  const handleTransferOwner = async () => {
    if (!adminTargetUser) return;
    try {
      await api.patch(`/threads/${activeThread.id}/owner`, { new_owner: adminTargetUser });
      setAdminTargetUser("");
      setShowAdminModal(false);
      fetchThreads();
      setStatus("Ownership Transferred");
    } catch (e) { setStatus("Admin Error"); }
  };

  const handleLogout = () => {
    localStorage.clear();
    setView("auth");
  };

  if (view === "auth") {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-influx-blue-950 text-slate-50 font-sans">
        <div className="w-full max-w-md p-8 bg-slate-900 rounded-2xl border border-slate-800 space-y-8 shadow-2xl">
          <div className="text-center space-y-2">
            <Shield className="w-16 h-16 text-influx-blue-400 mx-auto" />
            <h1 className="text-4xl font-bold tracking-tight">InFlux</h1>
            <p className="text-slate-400 text-lg">{authMode === "login" ? "Welcome back" : "Create your secure account"}</p>
          </div>
          <div className="space-y-4">
            <input type="text" placeholder="Username" className="w-full bg-slate-950 border border-slate-800 rounded-lg p-4 text-base outline-none focus:ring-2 focus:ring-influx-blue-500" value={username} onChange={(e) => setUsername(e.target.value)} />
            <input type="password" placeholder="Password" className="w-full bg-slate-950 border border-slate-800 rounded-lg p-4 text-base outline-none focus:ring-2 focus:ring-influx-blue-500" value={password} onChange={(e) => setPassword(e.target.value)} />
            <button onClick={handleAuth} className="w-full bg-influx-blue-600 hover:bg-influx-blue-500 py-4 rounded-lg font-bold text-lg flex items-center justify-center space-x-2 transition-all active:scale-[0.98]">{authMode === "login" ? <LogIn className="w-5 h-5" /> : <UserPlus className="w-5 h-5" />}<span>{authMode === "login" ? "Login" : "Register"}</span></button>
            <button onClick={() => setAuthMode(authMode === "login" ? "register" : "login")} className="w-full text-sm text-slate-500 hover:text-slate-300 transition-colors">{authMode === "login" ? "Need an account? Register" : "Have an account? Login"}</button>
          </div>
          <p className="text-xs text-center text-slate-600 font-mono uppercase tracking-widest">{status}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-white dark:bg-influx-blue-950 text-slate-900 dark:text-slate-50 overflow-hidden font-sans transition-colors duration-300">
      {/* Thread Modal */}
      {showThreadModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 w-full max-w-md rounded-2xl shadow-2xl">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <h3 className="text-2xl font-bold">{modalIsGroup ? "New Group" : "Direct Message"}</h3>
              <button onClick={() => setShowThreadModal(false)} className="text-slate-500 hover:text-influx-blue-500 transition-colors"><X className="w-6 h-6" /></button>
            </div>
            <div className="p-6 space-y-4">
              <input className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-base outline-none focus:ring-2 focus:ring-influx-blue-500" placeholder={modalIsGroup ? "Group Name" : "Username"} value={newThreadName} onChange={e => setNewThreadName(e.target.value)} />
              {modalIsGroup && <input className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-base outline-none focus:ring-2 focus:ring-influx-blue-500" placeholder="Members (comma separated)" value={newThreadMembers} onChange={e => setNewThreadMembers(e.target.value)} />}
              <button onClick={handleCreateThread} className="w-full bg-influx-blue-600 py-4 rounded-xl font-bold text-lg flex items-center justify-center space-x-2"><Plus className="w-5 h-5" /><span>Initialize</span></button>
            </div>
          </div>
        </div>
      )}

      {/* Admin Modal */}
      {showAdminModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 w-full max-w-md rounded-2xl shadow-2xl">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <h3 className="text-xl font-bold flex items-center space-x-2"><ShieldAlert className="w-6 h-6 text-influx-blue-500" /><span>Management</span></h3>
              <button onClick={() => setShowAdminModal(false)} className="text-slate-500 hover:text-influx-blue-500"><X className="w-6 h-6" /></button>
            </div>
            <div className="p-6 space-y-6">
              <div className="space-y-3">
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-widest">Add Member</label>
                  <div className="flex space-x-2">
                    <input className="flex-grow bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-4 py-3 text-base outline-none focus:ring-2 focus:ring-influx-blue-500" placeholder="Username" value={adminTargetUser} onChange={e => setAdminTargetUser(e.target.value)} />
                    <button onClick={handleAddMember} className="bg-emerald-600 hover:bg-emerald-500 p-3 rounded-lg transition-colors text-white"><UserPlus className="w-5 h-5" /></button>
                  </div>
              </div>
              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-4 text-center">
                <p className="text-sm text-slate-500">Ownership actions affect thread control</p>
                <button onClick={handleTransferOwner} className="w-full bg-rose-600/10 border border-rose-500/30 hover:bg-rose-600/20 text-rose-500 py-3 rounded-xl font-bold flex items-center justify-center space-x-2 transition-all">
                    <Crown className="w-5 h-5" />
                    <span>Transfer to {adminTargetUser || "..."}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar */}
      <aside className="w-72 border-r border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 flex flex-col">
        <div className="p-8 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-influx-blue-500" />
            <span className="font-bold tracking-tight text-2xl">InFlux</span>
          </div>
          <button onClick={toggleTheme} className="p-2 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg transition-colors">
            {theme === "dark" ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
          </button>
        </div>
        <nav className="flex-grow overflow-y-auto p-6 space-y-10">
          <div>
            <h3 className="text-xs uppercase tracking-[0.2em] text-slate-400 font-bold mb-4 px-2">Public</h3>
            <button onClick={() => { setActiveThread({ id: "global", name: "Global Channel", is_group: true }); fetchMessages("global"); }} className={`w-full flex items-center space-x-4 px-3 py-3 rounded-xl transition-all ${activeThread.id === 'global' ? 'bg-influx-blue-600 text-white shadow-lg shadow-influx-blue-500/20' : 'hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400'}`}><Hash className="w-5 h-5" /><span className="text-base font-bold">global</span></button>
          </div>
          <div>
            <div className="flex items-center justify-between mb-4 px-2">
                <h3 className="text-xs uppercase tracking-[0.2em] text-slate-400 font-bold">Secure Threads</h3>
                <button onClick={() => { setModalIsGroup(false); setShowThreadModal(true); }} className="text-influx-blue-500 hover:text-influx-blue-400"><Plus className="w-5 h-5" /></button>
            </div>
            <div className="space-y-1">
                {threads.filter(t => !t.is_group).map(t => (
                    <button key={t.id} onClick={() => { setActiveThread(t); fetchMessages(t.id); }} className={`w-full flex items-center space-x-4 px-3 py-3 rounded-xl transition-all ${activeThread.id === t.id ? 'bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-sm' : 'hover:bg-slate-200/50 dark:hover:bg-slate-800/50 text-slate-500 dark:text-slate-400'}`}><div className="w-2.5 h-2.5 rounded-full bg-emerald-500" /><span className="text-base font-medium truncate">{t.name}</span></button>
                ))}
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between mb-4 px-2">
                <h3 className="text-xs uppercase tracking-[0.2em] text-slate-400 font-bold">Groups</h3>
                <button onClick={() => { setModalIsGroup(true); setShowThreadModal(true); }} className="text-influx-blue-500 hover:text-influx-blue-400"><Plus className="w-5 h-5" /></button>
            </div>
            <div className="space-y-1">
                {threads.filter(t => t.is_group).map(t => (
                    <button key={t.id} onClick={() => { setActiveThread(t); fetchMessages(t.id); }} className={`w-full flex items-center space-x-4 px-3 py-3 rounded-xl transition-all ${activeThread.id === t.id ? 'bg-influx-blue-600 text-white shadow-lg' : 'hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400'}`}><Users className="w-5 h-5" /><span className="text-base font-medium truncate">{t.name}</span></button>
                ))}
            </div>
          </div>
        </nav>
        <div className="p-6 border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3"><div className="w-10 h-10 rounded-full bg-influx-blue-600 flex items-center justify-center font-bold text-white uppercase">{username.slice(0, 2)}</div><span className="text-base font-bold">@{username}</span></div>
                <button onClick={handleLogout} className="p-2 hover:bg-rose-500/10 rounded-lg text-rose-500"><LogOut className="w-5 h-5" /></button>
            </div>
        </div>
      </aside>

      {/* Main Area */}
      <main className="flex-grow flex flex-col">
        <header className="h-20 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-10 bg-white dark:bg-influx-blue-950/50 backdrop-blur-md">
            <div className="flex items-center space-x-4">
                <MessageSquare className="w-6 h-6 text-influx-blue-500" />
                <h2 className="font-bold text-2xl">{activeThread.name}</h2>
                {activeThread.owner === username && activeThread.id !== 'global' && (
                    <button onClick={() => setShowAdminModal(true)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-slate-400 hover:text-influx-blue-500"><ShieldAlert className="w-6 h-6" /></button>
                )}
            </div>
            <div className="flex items-center space-x-3 bg-slate-100 dark:bg-slate-900 px-4 py-2 rounded-full text-xs font-bold text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-800">
                <Lock className="w-4 h-4 text-emerald-500" />
                <span className="uppercase tracking-widest">E2EE Ready</span>
            </div>
        </header>

        <div className="flex-grow overflow-y-auto p-10 space-y-8 bg-[url('/grid.svg')] bg-center custom-scrollbar">
            {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center space-y-6 opacity-30 dark:opacity-20"><Shield className="w-24 h-24" /><p className="text-xl font-medium tracking-widest uppercase italic">Secure Channel Initialized</p></div>
            ) : (
                messages.map((m) => (
                    <div key={m.id} className={`flex flex-col ${m.sender === username ? 'items-end' : 'items-start'}`}>
                        <div className={`max-w-2xl p-5 rounded-2xl shadow-sm border ${m.sender === username ? 'bg-influx-blue-600 border-influx-blue-500 text-white' : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800'}`}>
                            <div className="flex items-center justify-between mb-2 space-x-12"><span className="text-xs font-black uppercase tracking-tighter opacity-70">@{m.sender}</span><span className="text-xs opacity-50 italic">{new Date(m.timestamp).toLocaleTimeString()}</span></div>
                            <p className="text-base leading-relaxed whitespace-pre-wrap">{m.content}</p>
                        </div>
                    </div>
                ))
            )}
        </div>

        <footer className="p-8 bg-white dark:bg-influx-blue-950 border-t border-slate-200 dark:border-slate-800">
            <div className="max-w-5xl mx-auto flex space-x-4">
                <input type="text" placeholder={`Secure message to ${activeThread.name}...`} className="flex-grow bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl px-6 py-4 text-base outline-none focus:ring-2 focus:ring-influx-blue-500 shadow-inner dark:shadow-none" value={messageInput} disabled={isSending} onChange={e => setMessageInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && sendMessage()} />
                <button onClick={sendMessage} disabled={isSending || !messageInput.trim()} className="bg-influx-blue-600 p-4 rounded-2xl hover:bg-influx-blue-500 transition-all active:scale-95 shadow-xl shadow-influx-blue-500/20 text-white disabled:bg-slate-300 dark:disabled:bg-slate-800"><Send className={`w-6 h-6 ${isSending ? 'animate-pulse' : ''}`} /></button>
            </div>
        </footer>
      </main>
    </div>
  );
}
