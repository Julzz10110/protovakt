use bytes::{Bytes, Buf};
use async_trait::async_trait;
use crate::core::{ProtocolHandler, ProcessingResult, ProcessingError, SessionId, Finding, Severity};

pub struct TlsHandler;

impl TlsHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for TlsHandler {
    fn name(&self) -> &str {
        "tls"
    }

    async fn can_handle(&self, data: &Bytes) -> bool {
        if data.len() < 5 {
            return false;
        }

        // TLS starts with content type (1 byte) + version (2 bytes) + length (2 bytes)
        let content_type = data[0];
        
        // Valid TLS content types: 20-23
        matches!(content_type, 20..=23)
    }

    async fn process_packet(
        &self,
        _session_id: &SessionId,
        data: Bytes,
    ) -> Result<ProcessingResult, ProcessingError> {
        if data.len() < 5 {
            return Err(ProcessingError::ParseError(
                "TLS packet too short".to_string()
            ));
        }

        let mut buf = data;
        let content_type = buf.get_u8();
        let version_major = buf.get_u8();
        let version_minor = buf.get_u8();
        let length = buf.get_u16() as usize;

        let mut findings = Vec::new();

        // Check TLS version
        let version = format!("{}.{}", version_major, version_minor);
        let tls_version = match (version_major, version_minor) {
            (3, 0) => "SSL 3.0",
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => "Unknown",
        };

        // Security checks
        if version_major == 3 && version_minor < 3 {
            findings.push(Finding {
                severity: Severity::High,
                category: "tls.version".to_string(),
                message: format!("Deprecated TLS version: {}", tls_version),
                details: Some(serde_json::json!({
                    "version": version,
                    "recommendation": "Use TLS 1.2 or higher"
                })),
            });
        }

        if version_major == 3 && version_minor == 0 {
            findings.push(Finding {
                severity: Severity::Critical,
                category: "tls.version".to_string(),
                message: "SSL 3.0 is insecure and should not be used".to_string(),
                details: Some(serde_json::json!({
                    "version": "SSL 3.0",
                    "cve": "POODLE"
                })),
            });
        }

        let parsed_data = serde_json::json!({
            "content_type": content_type,
            "version": version,
            "tls_version": tls_version,
            "length": length,
        });

        Ok(ProcessingResult {
            protocol: "tls".to_string(),
            parsed_data: Some(parsed_data),
            findings,
            next_protocol: Some("application".to_string()),
        })
    }
}
