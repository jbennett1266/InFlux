use spacetimedb::{reducer, table, Identity, ReducerContext, TableContext};

#[table(name = "user", public)]
pub struct User {
    #[primary_key]
    pub identity: Identity,
    pub username: String,
    pub status: String,
}

#[table(name = "thread", public)]
pub struct Thread {
    #[primary_key]
    pub id: String,
    pub name: String,
    pub is_group: bool,
    pub owner: Identity,
}

#[table(name = "membership", public)]
pub struct Membership {
    pub thread_id: String,
    pub user_identity: Identity,
}

#[table(name = "message", public)]
pub struct Message {
    #[primary_key]
    pub id: String,
    pub thread_id: String,
    pub sender_identity: Identity,
    pub content: String,
    pub timestamp: u64,
}

#[table(name = "streaming_peer", public)]
pub struct StreamingPeer {
    #[primary_key]
    pub user_identity: Identity,
    pub thread_id: String,
    pub signal_data: String, // WebRTC Offer/Answer/ICE
    pub stream_type: String, // "video" | "audio" | "screen"
}

#[reducer]
pub fn create_user(ctx: &ReducerContext, username: String) -> Result<(), String> {
    if User::filter_by_username(&username).is_some() {
        return Err("Username already taken".into());
    }
    User::insert(User {
        identity: ctx.sender,
        username,
        status: "online".into(),
    });
    Ok(())
}

#[reducer]
pub fn create_thread(
    ctx: &ReducerContext,
    name: String,
    is_group: bool,
    members: Vec<Identity>,
) -> Result<(), String> {
    let thread_id = uuid::Uuid::new_v4().to_string();
    Thread::insert(Thread {
        id: thread_id.clone(),
        name,
        is_group,
        owner: ctx.sender,
    });

    // Add owner as member
    Membership::insert(Membership {
        thread_id: thread_id.clone(),
        user_identity: ctx.sender,
    });

    for member in members {
        Membership::insert(Membership {
            thread_id: thread_id.clone(),
            user_identity: member,
        });
    }
    Ok(())
}

#[reducer]
pub fn send_message(
    ctx: &ReducerContext,
    thread_id: String,
    content: String,
) -> Result<(), String> {
    // Basic membership check
    if Membership::filter_by_thread_id(&thread_id)
        .find(|m| m.user_identity == ctx.sender)
        .is_none()
    {
        return Err("Not a member of this thread".into());
    }

    Message::insert(Message {
        id: uuid::Uuid::new_v4().to_string(),
        thread_id,
        sender_identity: ctx.sender,
        content,
        timestamp: ctx
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    Ok(())
}

#[reducer]
pub fn update_signal(
    ctx: &ReducerContext,
    thread_id: String,
    signal_data: String,
    stream_type: String,
) -> Result<(), String> {
    // Update or insert streaming peer info for signaling
    if let Some(mut peer) = StreamingPeer::filter_by_user_identity(&ctx.sender) {
        peer.signal_data = signal_data;
        peer.thread_id = thread_id;
        peer.stream_type = stream_type;
        StreamingPeer::update_by_user_identity(&ctx.sender, peer);
    } else {
        StreamingPeer::insert(StreamingPeer {
            user_identity: ctx.sender,
            thread_id,
            signal_data,
            stream_type,
        });
    }
    Ok(())
}
