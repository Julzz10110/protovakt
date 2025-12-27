use bytes::Bytes;
use async_trait::async_trait;
use crate::core::{ProtocolHandler, ProcessingResult, ProcessingError, SessionId};

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    pub payload: Bytes,
}

pub struct BaseProtocolHandler {
    name: String,
}

impl BaseProtocolHandler {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
        }
    }
}

#[async_trait]
impl ProtocolHandler for BaseProtocolHandler {
    fn name(&self) -> &str {
        &self.name
    }

    async fn can_handle(&self, _data: &Bytes) -> bool {
        false // Base handler doesn't handle anything
    }

    async fn process_packet(
        &self,
        _session_id: &SessionId,
        _data: Bytes,
    ) -> Result<ProcessingResult, ProcessingError> {
        Err(ProcessingError::UnknownProtocol)
    }
}
