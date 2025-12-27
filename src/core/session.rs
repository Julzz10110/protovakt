use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub Uuid);

#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: String,
    pub state: SessionState,
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Init,
    Handshake,
    Established,
    Closing,
    Closed,
    Error(String),
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<SessionId, Arc<RwLock<Session>>>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        protocol: String,
    ) -> SessionId {
        let id = SessionId(Uuid::new_v4());
        let session = Session {
            id: id.clone(),
            local_addr,
            remote_addr,
            protocol,
            state: SessionState::Init,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(id.clone(), Arc::new(RwLock::new(session)));
        id
    }

    pub async fn get_session(&self, id: &SessionId) -> Option<Arc<RwLock<Session>>> {
        let sessions = self.sessions.read().await;
        sessions.get(id).cloned()
    }

    pub async fn update_session_state(&self, id: &SessionId, state: SessionState) -> bool {
        if let Some(session) = self.get_session(id).await {
            let mut s = session.write().await;
            s.state = state;
            s.last_seen = chrono::Utc::now();
            true
        } else {
            false
        }
    }

    pub async fn remove_session(&self, id: &SessionId) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(id);
    }

    pub async fn list_sessions(&self) -> Vec<SessionId> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
