use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;

use crate::core::SessionId;

#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    fn name(&self) -> &str;
    
    async fn can_handle(&self, data: &Bytes) -> bool;
    
    async fn process_packet(
        &self,
        session_id: &SessionId,
        data: Bytes,
    ) -> Result<ProcessingResult, ProcessingError>;
}

#[derive(Debug, Clone)]
pub struct ProcessingResult {
    pub protocol: String,
    pub parsed_data: Option<serde_json::Value>,
    pub findings: Vec<Finding>,
    pub next_protocol: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    #[error("Protocol not recognized")]
    UnknownProtocol,
    
    #[error("Parsing error: {0}")]
    ParseError(String),
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

pub struct ProtocolDispatcher {
    handlers: HashMap<String, Box<dyn ProtocolHandler>>,
}

impl ProtocolDispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn register_handler(&mut self, handler: Box<dyn ProtocolHandler>) {
        let name = handler.name().to_string();
        self.handlers.insert(name, handler);
    }

    pub async fn dispatch(
        &self,
        session_id: &SessionId,
        data: Bytes,
    ) -> Result<ProcessingResult, ProcessingError> {
        // Try each handler to see if it can process this packet
        for (_, handler) in &self.handlers {
            if handler.can_handle(&data).await {
                return handler.process_packet(session_id, data).await;
            }
        }
        
        Err(ProcessingError::UnknownProtocol)
    }

    /// Detect protocol from packet data without processing
    pub async fn detect_protocol(&self, data: &Bytes) -> Option<String> {
        // Try each handler to detect protocol
        for (name, handler) in &self.handlers {
            if handler.can_handle(data).await {
                return Some(name.clone());
            }
        }
        None
    }
}

impl Default for ProtocolDispatcher {
    fn default() -> Self {
        Self::new()
    }
}



