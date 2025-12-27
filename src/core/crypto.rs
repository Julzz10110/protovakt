use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct CryptoContext {
    pub cipher_suite: Option<String>,
    pub key_material: Option<Vec<u8>>,
    pub master_secret: Option<Vec<u8>>,
    pub client_random: Option<Vec<u8>>,
    pub server_random: Option<Vec<u8>>,
}

impl CryptoContext {
    pub fn new() -> Self {
        Self {
            cipher_suite: None,
            key_material: None,
            master_secret: None,
            client_random: None,
            server_random: None,
        }
    }
}

pub struct CryptoContextManager {
    contexts: Arc<RwLock<HashMap<String, Arc<RwLock<CryptoContext>>>>>,
}

impl CryptoContextManager {
    pub fn new() -> Self {
        Self {
            contexts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_or_create(&self, session_id: &str) -> Arc<RwLock<CryptoContext>> {
        let mut contexts = self.contexts.write().await;
        contexts
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(CryptoContext::new())))
            .clone()
    }

    pub async fn remove(&self, session_id: &str) {
        let mut contexts = self.contexts.write().await;
        contexts.remove(session_id);
    }
}

impl Default for CryptoContextManager {
    fn default() -> Self {
        Self::new()
    }
}
