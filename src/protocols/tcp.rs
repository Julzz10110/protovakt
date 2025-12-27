use bytes::{Bytes, Buf};
use async_trait::async_trait;
use crate::core::{ProtocolHandler, ProcessingResult, ProcessingError, SessionId, Finding, Severity};

pub struct TcpHandler;

impl TcpHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolHandler for TcpHandler {
    fn name(&self) -> &str {
        "tcp"
    }

    async fn can_handle(&self, data: &Bytes) -> bool {
        // TCP header is at least 20 bytes
        if data.len() < 20 {
            return false;
        }
        
        // Basic TCP header validation
        // We'll assume if it's not obviously something else, it might be TCP
        true
    }

    async fn process_packet(
        &self,
        _session_id: &SessionId,
        data: Bytes,
    ) -> Result<ProcessingResult, ProcessingError> {
        if data.len() < 20 {
            return Err(ProcessingError::ParseError(
                "TCP packet too short".to_string()
            ));
        }

        let mut buf = data;
        
        // Parse TCP header (simplified)
        let src_port = buf.get_u16();
        let dst_port = buf.get_u16();
        let _seq_num = buf.get_u32();
        let _ack_num = buf.get_u32();
        let data_offset = (buf.get_u8() >> 4) & 0x0F;
        let flags = buf.get_u8();
        let _window = buf.get_u16();
        let _checksum = buf.get_u16();
        let _urgent = buf.get_u16();

        let mut findings = Vec::new();

        // Validate header length
        if data_offset < 5 {
            findings.push(Finding {
                severity: Severity::High,
                category: "tcp.header".to_string(),
                message: "Invalid TCP header length".to_string(),
                details: Some(serde_json::json!({
                    "data_offset": data_offset
                })),
            });
        }

        // Check for suspicious flags
        if flags & 0x01 != 0 && flags & 0x02 != 0 {
            // FIN and SYN together
            findings.push(Finding {
                severity: Severity::Medium,
                category: "tcp.flags".to_string(),
                message: "Suspicious TCP flags: FIN+SYN".to_string(),
                details: Some(serde_json::json!({
                    "flags": format!("0x{:02x}", flags)
                })),
            });
        }

        let parsed_data = serde_json::json!({
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": format!("0x{:02x}", flags),
            "data_offset": data_offset,
        });

        Ok(ProcessingResult {
            protocol: "tcp".to_string(),
            parsed_data: Some(parsed_data),
            findings,
            next_protocol: Some("application".to_string()),
        })
    }
}
