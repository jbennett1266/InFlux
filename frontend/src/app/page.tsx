"use client";

import React, { useState, useEffect } from "react";
import { Lock, Shield, Send, UserPlus, Key, LogIn, History, LogOut, Video } from "lucide-react";
import { spacetime } from "@/lib/spacetime";
import StreamingComponent from "./StreamingComponent";

export default function Home() {
  const [view, setView] = useState<"auth" | "dashboard">("auth");
  const [activeThread, setActiveThread] = useState<string>("global");
  const [username, setUsername] = useState("");
  const [messages, setMessages] = useState<any[]>([]);
  const [newMessage, setNewMessage] = useState("");

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    await spacetime.createUser(username);
    setView("dashboard");
  };

  const sendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newMessage.trim()) {
      await spacetime.sendMessage(activeThread, newMessage);
      setNewMessage("");
    }
  };

  if (view === "auth") {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-6 font-mono selection:bg-blue-500 selection:text-white">
        <div className="w-full max-w-md bg-gray-950 border border-blue-900/40 p-10 rounded-2xl shadow-2xl relative overflow-hidden group transition-all hover:border-blue-500/50">
          <div className="flex justify-center mb-8 relative">
            <div className="p-4 bg-blue-600/10 rounded-full border border-blue-500/20 group-hover:bg-blue-600/20 group-hover:border-blue-500/40 transition-all duration-500">
              <Shield className="w-10 h-10 text-blue-400" strokeWidth={1.5} />
            </div>
          </div>
          <h1 className="text-3xl font-black text-center mb-4 tracking-tighter text-white">INFLUX <span className="text-blue-500 italic">V2</span></h1>
          <p className="text-blue-400/60 text-center mb-10 text-xs uppercase tracking-widest font-bold">Realtime SpacetimeDB + Streaming</p>
          <form onSubmit={handleLogin} className="space-y-6">
            <div className="relative">
              <input type="text" placeholder="IDENTITY_USERNAME" className="w-full bg-black border border-gray-800 p-4 rounded-xl text-blue-300 placeholder:text-gray-700 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 text-white p-4 rounded-xl font-bold transition-all flex items-center justify-center space-x-3 shadow-lg shadow-blue-900/20 active:scale-95">
              <LogIn className="w-5 h-5" />
              <span>INITIALIZE_SESSION</span>
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-gray-300 flex font-mono selection:bg-blue-500 selection:text-white">
      {/* Sidebar */}
      <div className="w-72 bg-gray-950 border-r border-gray-900 flex flex-col p-6 space-y-8">
        <div className="flex items-center space-x-3 pb-6 border-b border-gray-900">
          <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse shadow-lg shadow-green-500/40" />
          <span className="text-xs font-bold text-white uppercase tracking-widest">LocalNode_Online</span>
        </div>
        <div className="space-y-3">
          <h2 className="text-[10px] font-black text-gray-600 uppercase tracking-[0.2em] mb-4">Channels</h2>
          {["global", "streaming-test", "private-thread"].map((channel) => (
            <button key={channel} onClick={() => setActiveThread(channel)} className={`w-full text-left p-3 rounded-lg text-xs font-bold transition-all border ${activeThread === channel ? "bg-blue-600/10 text-blue-400 border-blue-500/30" : "text-gray-500 border-transparent hover:bg-gray-900 hover:text-gray-300"}`}>
              # {channel.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        <header className="h-20 bg-gray-950 border-b border-gray-900 flex items-center justify-between px-10">
          <div className="flex flex-col">
            <h1 className="text-lg font-black text-white tracking-tighter uppercase">{activeThread}</h1>
            <span className="text-[10px] text-blue-500/60 font-bold uppercase tracking-widest">Spacetime Session Active</span>
          </div>
          <div className="flex space-x-4">
            <button onClick={() => setView("auth")} className="text-[10px] font-bold text-red-500/60 hover:text-red-400 transition-colors uppercase tracking-widest border border-red-900/20 px-3 py-1.5 rounded-md hover:bg-red-500/10">Terminate</button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-10 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-10">
            <StreamingComponent threadId={activeThread} currentUserIdentity={username} />
            <div className="p-4 bg-gray-900/30 border border-gray-800 rounded-lg flex flex-col justify-center">
               <p className="text-[10px] text-gray-500 mb-2 italic">// Streaming Peer Identity</p>
               <p className="text-xs font-bold text-blue-400">{username}@spacetimedb</p>
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-[10px] font-black text-gray-600 uppercase tracking-widest border-b border-gray-900 pb-2">Transmission Log</h3>
            {messages.map((msg, i) => (
              <div key={i} className="flex flex-col space-y-1 group">
                <div className="flex items-center space-x-2">
                  <span className="text-[10px] font-black text-blue-500 uppercase tracking-tighter">{msg.sender}</span>
                  <span className="text-[9px] text-gray-700 font-bold">{new Date(msg.timestamp * 1000).toLocaleTimeString()}</span>
                </div>
                <p className="text-sm text-gray-400 leading-relaxed group-hover:text-gray-200 transition-colors">{msg.content}</p>
              </div>
            ))}
            {messages.length === 0 && (
              <div className="py-20 flex flex-col items-center justify-center opacity-20">
                <History className="w-12 h-12 mb-4" />
                <span className="text-xs uppercase tracking-widest font-black">Waiting for Uplink...</span>
              </div>
            )}
          </div>
        </div>

        <footer className="p-8 bg-gray-950 border-t border-gray-900">
          <form onSubmit={sendMessage} className="relative group">
            <input type="text" placeholder={`MSG_TO: #${activeThread.toUpperCase()}`} className="w-full bg-black border border-gray-800 p-5 rounded-2xl text-blue-300 placeholder:text-gray-800 focus:outline-none focus:border-blue-500/50 transition-all text-sm shadow-2xl" value={newMessage} onChange={(e) => setNewMessage(e.target.value)} />
            <button type="submit" className="absolute right-4 top-1/2 -translate-y-1/2 p-2.5 bg-blue-600/10 hover:bg-blue-600 text-blue-500 hover:text-white rounded-xl transition-all">
              <Send className="w-5 h-5" />
            </button>
          </form>
        </footer>
      </div>
    </div>
  );
}
