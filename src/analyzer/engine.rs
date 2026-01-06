use anyhow::Result;
use bytes::Bytes;
use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;
use tracing::info;

use crate::core::{SessionManager, ProtocolDispatcher, SessionId, Finding, Severity};
use crate::protocols::{TcpHandler, TlsHandler, HttpHandler};
use crate::analyzer::capture::{PcapReader, PacketInfo};
use crate::analyzer::reporting::ReportGenerator;
use crate::utils::parse_address;

pub struct AnalyzerEngine {
    session_manager: Arc<SessionManager>,
    dispatcher: Arc<ProtocolDispatcher>,
    statistics: Arc<tokio::sync::RwLock<AnalysisStatistics>>,
    report_generator: ReportGenerator,
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
            report_generator: ReportGenerator::new(),
        }
    }

    pub async fn analyze_packet(
        &self,
        data: Bytes,
        source: String,
        destination: String,
    ) -> Result<()> {
        // Parse addresses
        let src_addr = parse_address(&source)
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let dst_addr = parse_address(&destination)
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        
        // Try to determine protocol from packet data first
        let detected_protocol = self.dispatcher.detect_protocol(&data).await
            .unwrap_or_else(|| "unknown".to_string());
        
        // Get or create session
        let session_id = self.session_manager
            .get_or_create_session(src_addr, dst_addr, detected_protocol.clone())
            .await;
        
        // Process the packet
        match self.dispatcher.dispatch(&session_id, data.clone()).await {
            Ok(result) => {
                // Update statistics
                let mut stats = self.statistics.write().await;
                stats.processed_packets += 1;
                stats.total_packets += 1;
                
                // Record protocol (use detected protocol if processing didn't identify one)
                let protocol = if result.protocol != "unknown" {
                    result.protocol.clone()
                } else {
                    detected_protocol
                };
                *stats.protocols_found.entry(protocol.clone()).or_insert(0) += 1;
                
                // Store findings (clone to avoid move)
                stats.findings.extend(result.findings.clone());
                
                tracing::debug!(
                    "Processed packet: protocol={}, findings={}",
                    protocol,
                    result.findings.len()
                );
            }
            Err(e) => {
                tracing::warn!("Failed to process packet: {}", e);
                let mut stats = self.statistics.write().await;
                stats.total_packets += 1;
                // Still record the detected protocol even if processing failed
                *stats.protocols_found.entry(detected_protocol).or_insert(0) += 1;
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
        use crate::analyzer::PcapReader;
        use tokio::time::{sleep, Duration};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        
        info!("Starting live capture on interface: {}", interface);
        if let Some(f) = filter {
            info!("BPF filter: {}", f);
        }
        
        let reader = PcapReader::new();
        let mut live_reader = reader.open_live(interface, filter)?;
        
        // Set timeout for packet reading (100ms)
        // This allows us to periodically check for shutdown signals
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        
        // Handle Ctrl+C gracefully
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            info!("Received shutdown signal, stopping capture...");
            running_clone.store(false, Ordering::Relaxed);
        });
        
        info!("Capturing packets (press Ctrl+C to stop)...");
        
        let mut packet_count = 0;
        let mut last_stats_time = std::time::Instant::now();
        
        loop {
            if !running.load(Ordering::Relaxed) {
                info!("Shutdown requested, stopping capture");
                break;
            }
            
            match live_reader.next_packet()? {
                Some(packet_info) => {
                    packet_count += 1;
                    
                    // Analyze the packet
                    if let Err(e) = self.analyze_packet(
                        packet_info.payload,
                        packet_info.source,
                        packet_info.destination,
                    ).await {
                        tracing::warn!("Failed to analyze packet: {}", e);
                    }
                    
                    // Print periodic statistics
                    if last_stats_time.elapsed().as_secs() >= 5 {
                        let stats = self.statistics.read().await;
                        info!(
                            "Captured: {} packets | Processed: {} | Findings: {} | Protocols: {:?}",
                            packet_count,
                            stats.processed_packets,
                            stats.findings.len(),
                            stats.protocols_found
                        );
                        last_stats_time = std::time::Instant::now();
                    }
                }
                None => {
                    // Timeout occurred, continue loop
                    sleep(Duration::from_millis(10)).await;
                }
            }
        }
        
        // Print final summary
        let stats = self.statistics.read().await;
        info!("Live capture complete!");
        info!("Total packets captured: {}", packet_count);
        info!("Total packets processed: {}", stats.processed_packets);
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

    pub async fn generate_reports<P: AsRef<Path>>(
        &self,
        output_dir: P,
        formats: &[String],
    ) -> Result<Vec<String>> {
        let stats = self.statistics.read().await;
        self.report_generator.save_report(&stats, output_dir, formats)
    }
}

impl Default for AnalyzerEngine {
    fn default() -> Self {
        Self::new()
    }
}
