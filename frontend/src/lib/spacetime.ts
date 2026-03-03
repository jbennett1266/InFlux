export interface User {
    identity: string;
    username: string;
    status: string;
}

export interface Message {
    id: string;
    thread_id: string;
    sender_identity: string;
    content: string;
    timestamp: number;
}

/**
 * SpacetimeManager Mock
 * 
 * NOTE: Due to internal SDK v2.0.2 instantiation complexities that require 
 * code generation (spacetime generate), this mock provides the functional 
 * interface for the InFlux V2 prototype. 
 * 
 * Real production deployment requires running:
 * 1. spacetime publish -d influx_chat
 * 2. spacetime generate --lang typescript
 */
class SpacetimeManager {
    private listeners: ((msg: Message) => void)[] = [];
    private messages: Message[] = [];
    private username: string = "";

    async connect(username: string) {
        console.log("Mock SpacetimeDB: Initializing connection for", username);
        this.username = username;
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 500));
        console.log("Mock SpacetimeDB: Connected.");
        return Promise.resolve();
    }

    onMessage(callback: (msg: Message) => void) {
        this.listeners.push(callback);
    }

    async createUser(username: string) {
        console.log("Mock SpacetimeDB: Creating user", username);
        return Promise.resolve();
    }

    async sendMessage(threadId: string, content: string) {
        console.log("Mock SpacetimeDB: Sending message to", threadId);
        
        const mockMsg: Message = {
            id: Math.random().toString(36).substring(7),
            thread_id: threadId,
            sender_identity: this.username,
            content: content,
            timestamp: Math.floor(Date.now() / 1000)
        };

        // Simulate local persistence and broadcast
        this.messages.push(mockMsg);
        this.listeners.forEach(l => l(mockMsg));
        
        return Promise.resolve();
    }

    async updateSignal(threadId: string, signalData: string, streamType: string) {
        console.log("Mock SpacetimeDB: Signaling", streamType, "on", threadId);
        return Promise.resolve();
    }
}

export const spacetime = new SpacetimeManager();
