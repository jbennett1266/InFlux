import { SpacetimeDBClient, Identity } from "spacetimedb";

// Note: In a real SpacetimeDB app, these types are usually generated 
// by `spacetimedb generate`. Here we define them manually for the prototype.

export interface User {
    identity: string;
    username: string;
    status: string;
}

export interface Thread {
    id: string;
    name: string;
    is_group: boolean;
    owner: string;
}

export interface Message {
    id: string;
    thread_id: string;
    sender_identity: string;
    content: string;
    timestamp: number;
}

export interface StreamingPeer {
    user_identity: string;
    thread_id: string;
    signal_data: string;
    stream_type: string;
}

class SpacetimeManager {
    private client: SpacetimeDBClient | null = null;
    private dbName = "influx_chat";
    private host = "http://localhost:3000";

    async connect() {
        // This is a placeholder for actual connection logic
        // SpacetimeDB SDK typically handles identity and subscriptions
        console.log("Connecting to SpacetimeDB...");
    }

    // Wrappers for reducers
    async createUser(username: String) {
        console.log("Calling reducer: create_user", username);
    }

    async sendMessage(threadId: string, content: string) {
        console.log("Calling reducer: send_message", threadId, content);
    }

    async updateSignal(threadId: string, signalData: string, streamType: string) {
        console.log("Calling reducer: update_signal", threadId, streamType);
    }
}

export const spacetime = new SpacetimeManager();
