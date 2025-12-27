use anyhow::Result;
use clap::Args;
use tracing::info;
use std::time::Duration;

use crate::fuzzer::FuzzerEngine;
use crate::utils::parse_duration;

#[derive(Args)]
pub struct FuzzCommand {
    /// Target endpoint (tcp://host:port, udp://host:port)
    #[arg(short, long)]
    pub target: Option<String>,

    /// Duration of fuzzing (e.g., "1h", "30m", "24h")
    #[arg(short, long)]
    pub duration: Option<String>,

    /// Corpus directory for mutation-based fuzzing
    #[arg(short, long)]
    pub corpus: Option<String>,

    /// Fuzzing strategy (grammar, mutation, stateful, coverage)
    #[arg(short, long, default_value = "stateful")]
    pub strategy: String,

    /// Protocol to fuzz
    #[arg(short, long, required = true)]
    pub protocol: String,

    /// Maximum requests per second
    #[arg(long, default_value = "100")]
    pub max_rps: u64,

    /// Memory limit in MB
    #[arg(long, default_value = "4096")]
    pub memory_mb: u64,
}

impl FuzzCommand {
    pub async fn run(self) -> Result<()> {
        info!("Running fuzz command");
        info!("Protocol: {}", self.protocol);
        info!("Strategy: {}", self.strategy);
        
        let target = self.target.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--target is required"))?;
        
        let duration = if let Some(dur_str) = &self.duration {
            Some(parse_duration(dur_str)?)
        } else {
            None
        };
        
        info!("Target: {}", target);
        if let Some(dur) = &duration {
            info!("Duration: {:?}", dur);
        }

        let engine = FuzzerEngine::new();
        engine.run(target, &self.protocol, &self.strategy, duration).await?;
        
        Ok(())
    }
}
