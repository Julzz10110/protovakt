use anyhow::Result;
use bytes::Bytes;
use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;
use tracing::info;

use crate::core::{SessionManager, ProtocolDispatcher, SessionId, Finding, Severity};
use crate::protocols::{TcpHandler, TlsHandler, HttpHandler};
use crate::analyzer::capture::{PcapReader, PacketInfo};

pub struct AnalyzerEngine {
    session_manager: Arc<SessionManager>,
    dispatcher: Arc<ProtocolDispatcher>,
    statistics: Arc<tokio::sync::RwLock<AnalysisStatistics>>,
}

#[derive(Debug, Default)]
pub struct AnalysisStatistics {
    pub total_packets: u64,
    pub processed_packets: u64,
    pub findings: Vec<Finding>,
    pub protocols_found: HashMap<String, u64>,
}

impl AnalyzerEngine {
    pub fn new() -> Self {
        let mut dispatcher = ProtocolDispatcher::new();
        
        // Register protocol handlers
        dispatcher.register_handler(Box::new(TcpHandler::new()));
        dispatcher.register_handler(Box::new(TlsHandler::new()));
        dispatcher.register_handler(Box::new(HttpHandler::new()));

        Self {
            session_manager: Arc::new(SessionManager::new()),
            dispatcher: Arc::new(dispatcher),
            statistics: Arc::new(tokio::sync::RwLock::new(AnalysisStatistics::default())),
        }
    }

    pub async fn analyze_packet(
        &self,
        data: Bytes,
        source: String,
        destination: String,
    ) -> Result<()> {
        // Create or get session
        let session_id = self.session_manager
            .create_session(
                source.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                destination.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                "unknown".to_string(),
            )
            .await;
        
        // Process the packet
        match self.dispatcher.dispatch(&session_id, data.clone()).await {
            Ok(result) => {
                // Update statistics
                let mut stats = self.statistics.write().await;
                stats.processed_packets += 1;
                stats.total_packets += 1;
                
                // Record protocol
                *stats.protocols_found.entry(result.protocol.clone()).or_insert(0) += 1;
                
                // Store findings (clone to avoid move)
                stats.findings.extend(result.findings.clone());
                
                tracing::debug!(
                    "Processed packet: protocol={}, findings={}",
                    result.protocol,
                    result.findings.len()
                );
            }
            Err(e) => {
                tracing::warn!("Failed to process packet: {}", e);
                let mut stats = self.statistics.write().await;
                stats.total_packets += 1;
            }
        }
        
        Ok(())
    }

    pub async fn analyze_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let reader = PcapReader::new();
        let mut pcap_reader = reader.read_file(path)?;
        
        info!("Starting PCAP file analysis...");
        
        let mut packet_count = 0;
        loop {
            match pcap_reader.next_packet()? {
                Some(packet_info) => {
                    packet_count += 1;
                    
                    if packet_count % 1000 == 0 {
                        info!("Processed {} packets...", packet_count);
                    }
                    
                    // Analyze the packet
                    self.analyze_packet(
                        packet_info.payload,
                        packet_info.source,
                        packet_info.destination,
                    ).await?;
                }
                None => break,
            }
        }
        
        // Print summary
        let stats = self.statistics.read().await;
        info!("Analysis complete!");
        info!("Total packets: {}", stats.total_packets);
        info!("Processed packets: {}", stats.processed_packets);
        info!("Total findings: {}", stats.findings.len());
        info!("Protocols found: {:?}", stats.protocols_found);
        
        // Print findings summary
        if !stats.findings.is_empty() {
            let mut by_severity: HashMap<String, usize> = HashMap::new();
            for finding in &stats.findings {
                let severity = match finding.severity {
                    Severity::Critical => "Critical",
                    Severity::High => "High",
                    Severity::Medium => "Medium",
                    Severity::Low => "Low",
                    Severity::Info => "Info",
                };
                *by_severity.entry(severity.to_string()).or_insert(0) += 1;
            }
            
            info!("Findings by severity: {:?}", by_severity);
        }
        
        Ok(())
    }

    pub async fn analyze_live(&self, interface: &str, filter: Option<&str>) -> Result<()> {
        // TODO: Implement live capture
        tracing::warn!("Live capture not yet implemented");
        Ok(())
    }
}

impl Default for AnalyzerEngine {
    fn default() -> Self {
        Self::new()
    }
}
