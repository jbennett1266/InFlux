#[cfg(not(feature = "test-env"))]
use spacetimedb::{spacetimedb, Identity, ReducerContext};

#[cfg(feature = "test-env")]
pub mod mock {
    pub use serde::{Deserialize, Serialize};
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub struct Identity([u8; 32]);
    impl Identity {
        pub fn dummy() -> Self {
            Self([0u8; 32])
        }
    }
    pub struct ReducerContext {
        pub sender: Identity,
        pub timestamp: u64,
    }
}

#[cfg(feature = "test-env")]
use mock::*;

#[cfg_attr(not(feature = "test-env"), spacetimedb(table))]
#[cfg_attr(feature = "test-env", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    #[cfg_attr(not(feature = "test-env"), primarykey)]
    pub identity: Identity,
    pub username: String,
    pub status: String,
}

#[cfg_attr(not(feature = "test-env"), spacetimedb(table))]
#[cfg_attr(feature = "test-env", derive(serde::Serialize, serde::Deserialize))]
pub struct Thread {
    #[cfg_attr(not(feature = "test-env"), primarykey)]
    pub id: String,
    pub name: String,
    pub is_group: bool,
    pub owner: Identity,
}

#[cfg_attr(not(feature = "test-env"), spacetimedb(table))]
#[cfg_attr(feature = "test-env", derive(serde::Serialize, serde::Deserialize))]
pub struct Membership {
    pub thread_id: String,
    pub user_identity: Identity,
}

#[cfg_attr(not(feature = "test-env"), spacetimedb(table))]
#[cfg_attr(feature = "test-env", derive(serde::Serialize, serde::Deserialize))]
pub struct Message {
    #[cfg_attr(not(feature = "test-env"), primarykey)]
    pub id: String,
    pub thread_id: String,
    pub sender_identity: Identity,
    pub content: String,
    pub timestamp: u64,
}

#[cfg_attr(not(feature = "test-env"), spacetimedb(table))]
#[cfg_attr(feature = "test-env", derive(serde::Serialize, serde::Deserialize))]
pub struct StreamingPeer {
    #[cfg_attr(not(feature = "test-env"), primarykey)]
    pub user_identity: Identity,
    pub thread_id: String,
    pub signal_data: String,
    pub stream_type: String,
}

// Logic implementations that work in both environments
pub fn logic_create_user(
    sender: Identity,
    username: String,
    existing_users: Vec<User>,
) -> Result<User, String> {
    if existing_users.iter().any(|u| u.username == username) {
        return Err("Username already taken".into());
    }
    Ok(User {
        identity: sender,
        username,
        status: "online".into(),
    })
}

pub fn logic_send_message(
    sender: Identity,
    thread_id: String,
    content: String,
    memberships: Vec<Membership>,
) -> Result<Message, String> {
    if !memberships
        .iter()
        .any(|m| m.thread_id == thread_id && m.user_identity == sender)
    {
        return Err("Not a member".into());
    }
    Ok(Message {
        id: "msg_id".into(),
        thread_id,
        sender_identity: sender,
        content,
        timestamp: 0,
    })
}

#[cfg(not(feature = "test-env"))]
#[spacetimedb(reducer)]
pub fn create_user(ctx: ReducerContext, username: String) -> Result<(), String> {
    let existing = User::iter().collect();
    let user = logic_create_user(ctx.sender, username, existing)?;
    User::insert(user).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(feature = "test-env"))]
#[spacetimedb(reducer)]
pub fn send_message(ctx: ReducerContext, thread_id: String, content: String) -> Result<(), String> {
    let memberships = Membership::iter().collect();
    let msg = logic_send_message(ctx.sender, thread_id, content, memberships)?;
    Message::insert(msg).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation_logic() {
        let identity = Identity::dummy();
        let res = logic_create_user(identity, "alice".into(), vec![]);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().username, "alice");

        let res_fail = logic_create_user(
            identity,
            "alice".into(),
            vec![User {
                identity,
                username: "alice".into(),
                status: "online".into(),
            }],
        );
        assert!(res_fail.is_err());
    }

    #[test]
    fn test_message_membership_logic() {
        let alice = Identity::dummy();
        let res = logic_send_message(
            alice,
            "t1".into(),
            "hi".into(),
            vec![Membership {
                thread_id: "t1".into(),
                user_identity: alice,
            }],
        );
        assert!(res.is_ok());

        let res_fail = logic_send_message(alice, "t1".into(), "hi".into(), vec![]);
        assert!(res_fail.is_err());
    }
}
