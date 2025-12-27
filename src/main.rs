mod cli;
mod config;
mod core;
mod analyzer;
mod fuzzer;
mod protocols;
mod utils;

use anyhow::Result;
use clap::Parser;
use tracing::{info, error};

use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "protovakt=info".into())
        )
        .init();

    info!("Starting protovakt v{}", env!("CARGO_PKG_VERSION"));

    let cli = Cli::parse();
    
    match cli.run().await {
        Ok(_) => {
            info!("Command completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Command failed: {}", e);
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}