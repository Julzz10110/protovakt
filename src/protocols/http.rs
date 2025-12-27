use bytes::Bytes;
use async_trait::async_trait;
use crate::core::{ProtocolHandler, ProcessingResult, ProcessingError, SessionId, Finding, Severity};

pub struct HttpHandler;

impl HttpHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for HttpHandler {
    fn name(&self) -> &str {
        "http"
    }

    async fn can_handle(&self, data: &Bytes) -> bool {
        // Check for HTTP request/response signatures
        if data.len() < 4 {
            return false;
        }

        let start = std::str::from_utf8(&data[..data.len().min(20)]);
        if let Ok(start) = start {
            start.starts_with("GET ")
                || start.starts_with("POST ")
                || start.starts_with("PUT ")
                || start.starts_with("DELETE ")
                || start.starts_with("HEAD ")
                || start.starts_with("OPTIONS ")
                || start.starts_with("HTTP/")
        } else {
            false
        }
    }

    async fn process_packet(
        &self,
        _session_id: &SessionId,
        data: Bytes,
    ) -> Result<ProcessingResult, ProcessingError> {
        let text = String::from_utf8_lossy(&data);
        let lines: Vec<&str> = text.lines().collect();
        
        if lines.is_empty() {
            return Err(ProcessingError::ParseError(
                "Empty HTTP message".to_string()
            ));
        }

        let mut findings = Vec::new();
        let first_line = lines[0];

        // Parse request or response
        let is_request = first_line.starts_with("GET ")
            || first_line.starts_with("POST ")
            || first_line.starts_with("PUT ")
            || first_line.starts_with("DELETE ");

        let parsed_data = if is_request {
            // Parse HTTP request
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(ProcessingError::ParseError(
                    "Invalid HTTP request line".to_string()
                ));
            }

            let method = parts[0];
            let path = parts[1];

            // Security checks
            if path.contains("..") {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: "http.path".to_string(),
                    message: "Potential path traversal attempt".to_string(),
                    details: Some(serde_json::json!({
                        "path": path
                    })),
                });
            }

            serde_json::json!({
                "type": "request",
                "method": method,
                "path": path,
            })
        } else {
            // Parse HTTP response
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(ProcessingError::ParseError(
                    "Invalid HTTP response line".to_string()
                ));
            }

            let version = parts[0];
            let status_code: u16 = parts[1].parse().unwrap_or(0);

            // Security checks
            if !version.starts_with("HTTP/") {
                findings.push(Finding {
                    severity: Severity::Low,
                    category: "http.version".to_string(),
                    message: "Invalid HTTP version format".to_string(),
                    details: Some(serde_json::json!({
                        "version": version
                    })),
                });
            }

            serde_json::json!({
                "type": "response",
                "version": version,
                "status_code": status_code,
            })
        };

        Ok(ProcessingResult {
            protocol: "http".to_string(),
            parsed_data: Some(parsed_data),
            findings,
            next_protocol: None,
        })
    }
}
