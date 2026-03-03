"use client";

import React, { useState, useRef, useEffect } from "react";
import { spacetime } from "@/lib/spacetime";
import { Video, Mic, Monitor, PhoneOff } from "lucide-react";

interface StreamingComponentProps {
    threadId: string;
    currentUserIdentity: string;
}

export default function StreamingComponent({ threadId, currentUserIdentity }: StreamingComponentProps) {
    const [stream, setStream] = useState<any>(null);
    const [type, setType] = useState<"video" | "audio" | "screen" | null>(null);
    const [isMounted, setIsMounted] = useState(false);
    const videoRef = useRef<HTMLVideoElement>(null);
    const peerConnection = useRef<any>(null);

    useEffect(() => {
        setIsMounted(true);
    }, []);

    const startStream = async (streamType: "video" | "audio" | "screen") => {
        if (typeof window === "undefined") return;
        try {
            let mediaStream: MediaStream;
            if (streamType === "screen") {
                mediaStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
            } else {
                mediaStream = await navigator.mediaDevices.getUserMedia({
                    video: streamType === "video",
                    audio: true
                });
            }

            setStream(mediaStream);
            setType(streamType);
            if (videoRef.current) videoRef.current.srcObject = mediaStream;

            // Setup WebRTC PeerConnection for signaling via SpacetimeDB
            const pc = new RTCPeerConnection({
                iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
            });

            mediaStream.getTracks().forEach(track => pc.addTrack(track, mediaStream));

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    // Send candidate as part of signal_data to SpacetimeDB
                    const signal = JSON.stringify({ type: "ice", candidate: event.candidate });
                    spacetime.updateSignal(threadId, signal, streamType);
                }
            };

            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            
            // Send offer to SpacetimeDB
            await spacetime.updateSignal(threadId, JSON.stringify(offer), streamType);
            
            peerConnection.current = pc;
        } catch (error) {
            console.error("Streaming error:", error);
        }
    };

    const stopStream = () => {
        if (stream) {
            (stream as MediaStream).getTracks().forEach(track => track.stop());
        }
        setStream(null);
        setType(null);
        peerConnection.current?.close();
    };

    if (!isMounted) return null;

    return (
        <div className="p-4 bg-gray-900 rounded-lg shadow-xl border border-blue-500/30">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-blue-400 uppercase tracking-wider">Live Stream</h3>
                <div className="flex space-x-2">
                    <button onClick={() => startStream("video")} className="p-2 hover:bg-blue-500/20 rounded-full transition-colors">
                        <Video size={18} className="text-blue-400" />
                    </button>
                    <button onClick={() => startStream("audio")} className="p-2 hover:bg-green-500/20 rounded-full transition-colors">
                        <Mic size={18} className="text-green-400" />
                    </button>
                    <button onClick={() => startStream("screen")} className="p-2 hover:bg-purple-500/20 rounded-full transition-colors">
                        <Monitor size={18} className="text-purple-400" />
                    </button>
                    {stream && (
                        <button onClick={stopStream} className="p-2 hover:bg-red-500/20 rounded-full transition-colors">
                            <PhoneOff size={18} className="text-red-400" />
                        </button>
                    )}
                </div>
            </div>

            <div className="relative aspect-video bg-black rounded overflow-hidden border border-gray-800">
                {stream ? (
                    <video ref={videoRef} autoPlay playsInline muted className="w-full h-full object-contain" />
                ) : (
                    <div className="absolute inset-0 flex items-center justify-center text-gray-700">
                        <span className="text-xs italic">No active stream</span>
                    </div>
                )}
                {type && (
                    <div className="absolute top-2 left-2 px-2 py-0.5 bg-red-600 text-[10px] font-bold text-white rounded uppercase animate-pulse">
                        Live {type}
                    </div>
                )}
            </div>
        </div>
    );
}
