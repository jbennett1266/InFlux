import { DbConnectionBuilder, DbConnectionImpl } from "spacetimedb/sdk";

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

// Minimal RemoteModule definition for untyped usage
const REMOTE_MODULE: any = {
    tables: {},
    reducers: {},
    procedures: [],
    versionInfo: { cliVersion: "2.0.0" }
};

class SpacetimeManager {
    private conn: any | null = null;
    private dbName = "influx_chat";
    private host = "ws://localhost:3000";
    private listeners: ((msg: Message) => void)[] = [];

    async connect(username: string) {
        if (this.conn) return;

        console.log("Initializing SpacetimeDB connection...");

        // Manually instantiate the builder since the generated DbConnection class is missing
        const builder = new DbConnectionBuilder(REMOTE_MODULE, (config) => new DbConnectionImpl(config));
        
        this.conn = builder
            .withUri(this.host)
            .withDatabaseName(this.dbName)
            .onConnect((conn: any, identity: any, token: string) => {
                console.log("Connected to SpacetimeDB as", identity.toHexString());
                conn.subscriptionBuilder()
                    .subscribe(["SELECT * FROM user", "SELECT * FROM message", "SELECT * FROM thread", "SELECT * FROM membership"]);
                
                this.createUser(username);
            })
            .onConnectError((_ctx: any, err: Error) => {
                console.error("Connection error:", err);
            })
            .build();

        // Register table listeners via the untyped API
        // In v2, table access is usually via conn.db.tableName
        if (this.conn.db && this.conn.db.message) {
            this.conn.db.message.onInsert((row: any) => {
                this.listeners.forEach(l => l(row));
            });
        }
    }

    onMessage(callback: (msg: Message) => void) {
        this.listeners.push(callback);
    }

    async createUser(username: string) {
        if (this.conn) {
            // Call reducer by name
            this.conn.callReducer("create_user", [username]);
        }
    }

    async sendMessage(threadId: string, content: string) {
        if (this.conn) {
            this.conn.callReducer("send_message", [threadId, content]);
        }
    }

    async updateSignal(threadId: string, signalData: string, streamType: string) {
        if (this.conn) {
            this.conn.callReducer("update_signal", [threadId, signalData, streamType]);
        }
    }
}

export const spacetime = new SpacetimeManager();
