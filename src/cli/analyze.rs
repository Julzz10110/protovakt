use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::analyzer::AnalyzerEngine;

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
        
        let engine = AnalyzerEngine::new();
        
        if let Some(input) = &self.input {
            info!("Input file: {}", input);
            engine.analyze_file(input).await?;
        } else if let Some(live) = &self.live {
            info!("Live capture from: {}", live);
            engine.analyze_live(live, self.filter.as_deref()).await?;
        } else {
            anyhow::bail!("Either --input or --live must be specified");
        }
        
        Ok(())
    }
}
