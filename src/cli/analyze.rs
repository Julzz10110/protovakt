use anyhow::{Result, Context};
use clap::Args;
use tracing::info;
use std::path::Path;

use crate::analyzer::{AnalyzerEngine, PcapReader};

#[derive(Args)]
pub struct AnalyzeCommand {
    /// Input file (PCAP) or interface name for live capture
    #[arg(short, long)]
    pub input: Option<String>,

    /// Live capture from network interface
    #[arg(short, long)]
    pub live: Option<String>,

    /// BPF filter expression
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Protocol to analyze (quic, http3, grpc, mqtt, kafka)
    #[arg(short, long, default_value = "auto")]
    pub protocol: String,

    /// Output directory for reports
    #[arg(short, long, default_value = "./reports")]
    pub output: String,

    /// Enable compliance checking
    #[arg(long)]
    pub compliance: bool,

    /// Enable performance analysis
    #[arg(long)]
    pub performance: bool,
}

impl AnalyzeCommand {
    pub async fn run(self) -> Result<()> {
        info!("Running analysis command");
        info!("Protocol: {}", self.protocol);
        
        // Validate protocol parameter
        let valid_protocols = ["auto", "tcp", "tls", "http", "quic", "http3", "grpc", "mqtt", "kafka"];
        if !valid_protocols.contains(&self.protocol.as_str()) {
            anyhow::bail!(
                "Invalid protocol: {}. Valid options: {}",
                self.protocol,
                valid_protocols.join(", ")
            );
        }
        
        // Validate output directory
        let output_path = Path::new(&self.output);
        if !output_path.exists() {
            std::fs::create_dir_all(output_path)
                .context(format!("Failed to create output directory: {}", self.output))?;
        } else if !output_path.is_dir() {
            anyhow::bail!("Output path exists but is not a directory: {}", self.output);
        }
        
        let engine = AnalyzerEngine::new();
        
        if let Some(input) = &self.input {
            // Validate input file exists
            let input_path = Path::new(input);
            if !input_path.exists() {
                anyhow::bail!("Input file does not exist: {}", input);
            }
            if !input_path.is_file() {
                anyhow::bail!("Input path is not a file: {}", input);
            }
            
            // Check file extension
            let extension = input_path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("");
            let valid_extensions = ["pcap", "cap", "pcapng"];
            if !valid_extensions.contains(&extension.to_lowercase().as_str()) {
                tracing::warn!(
                    "File extension '{}' is not a standard PCAP format. Continuing anyway...",
                    extension
                );
            }
            
            info!("Input file: {}", input);
            engine.analyze_file(input).await?;
        } else if let Some(live) = &self.live {
            // Validate network interface exists
            let reader = PcapReader::new();
            let devices = reader.list_devices()
                .context("Failed to list network devices")?;
            
            if !devices.contains(live) {
                anyhow::bail!(
                    "Network interface '{}' not found. Available interfaces: {}",
                    live,
                    devices.join(", ")
                );
            }
            
            info!("Live capture from: {}", live);
            engine.analyze_live(live, self.filter.as_deref()).await?;
        } else {
            anyhow::bail!("Either --input or --live must be specified");
        }
        
        // Generate reports
        let formats = vec!["json".to_string(), "html".to_string()];
        let saved_files = engine.generate_reports(&self.output, &formats).await?;
        
        if !saved_files.is_empty() {
            info!("Reports saved:");
            for file in &saved_files {
                info!("  - {}", file);
            }
        }
        
        Ok(())
    }
}
