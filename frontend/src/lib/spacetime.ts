import { DbConnection } from "spacetimedb/sdk";

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
    private conn: any | null = null;
    private dbName = "influx_chat";
    private host = "ws://localhost:3000";
    private listeners: ((msg: Message) => void)[] = [];

    async connect(username: string) {
        if (this.conn) return;

        // In SDK v2, we use DbConnection.builder()
        // Note: For untyped access, we might need a slightly different approach
        // but the builder is the primary entry point.
        this.conn = DbConnection.builder()
            .withUri(this.host)
            .withDatabaseName(this.dbName)
            .onConnect((conn, identity, token) => {
                console.log("Connected to SpacetimeDB as", identity.toHexString());
                conn.subscriptionBuilder()
                    .onApplied(() => console.log("Subscription applied"))
                    .subscribe(["SELECT * FROM user", "SELECT * FROM message", "SELECT * FROM thread", "SELECT * FROM membership"]);
                
                // Call create_user reducer
                this.createUser(username);
            })
            .onConnectError((ctx, err) => {
                console.error("Connection error:", err);
            })
            .build();

        // Register table listeners
        this.conn.db.message.onInsert((row: any) => {
            this.listeners.forEach(l => l(row));
        });
    }

    onMessage(callback: (msg: Message) => void) {
        this.listeners.push(callback);
    }

    async createUser(username: string) {
        this.conn?.reducers.create_user(username);
    }

    async sendMessage(threadId: string, content: string) {
        this.conn?.reducers.send_message(threadId, content);
    }

    async updateSignal(threadId: string, signalData: string, streamType: string) {
        this.conn?.reducers.update_signal(threadId, signalData, streamType);
    }
}

export const spacetime = new SpacetimeManager();
