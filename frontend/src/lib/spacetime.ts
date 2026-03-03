import { SpacetimeDBClient } from "spacetimedb/sdk";

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

class SpacetimeManager {
    private client: SpacetimeDBClient | null = null;
    private dbName = "influx_chat";
    private host = "ws://localhost:3000";
    private listeners: ((msg: Message) => void)[] = [];

    async connect(username: string) {
        if (this.client) return;

        this.client = new SpacetimeDBClient(this.host, this.dbName);
        
        this.client.onConnect(() => {
            console.log("Connected to SpacetimeDB");
            this.client?.subscribe(["SELECT * FROM user", "SELECT * FROM message", "SELECT * FROM thread", "SELECT * FROM membership"]);
        });

        this.client.onItemInserted((table, row) => {
            if (table.name === "message") {
                const msg = row as unknown as Message;
                this.listeners.forEach(l => l(msg));
            }
        });

        await this.client.connect();
        this.createUser(username);
    }

    onMessage(callback: (msg: Message) => void) {
        this.listeners.push(callback);
    }

    async createUser(username: string) {
        this.client?.call("create_user", [username]);
    }

    async sendMessage(threadId: string, content: string) {
        this.client?.call("send_message", [threadId, content]);
    }

    async updateSignal(threadId: string, signalData: string, streamType: string) {
        this.client?.call("update_signal", [threadId, signalData, streamType]);
    }
}

export const spacetime = new SpacetimeManager();
