mod analyze;
mod fuzz;
mod ci;
mod plugin;
mod config_cmd;

use anyhow::Result;
use clap::{Parser, Subcommand};

use self::analyze::AnalyzeCommand;
use self::fuzz::FuzzCommand;
use self::ci::CiCommand;
use self::plugin::PluginCommand;
use self::config_cmd::ConfigCommand;

#[derive(Parser)]
#[command(name = "protovakt")]
#[command(about = "Protocol analysis and fuzzing system", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze network traffic
    Analyze(AnalyzeCommand),
    
    /// Fuzz protocol implementations
    Fuzz(FuzzCommand),
    
    /// CI/CD integration mode
    Ci(CiCommand),
    
    /// Plugin management
    Plugin(PluginCommand),
    
    /// Configuration management
    Config(ConfigCommand),
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        match self.command {
            Commands::Analyze(cmd) => cmd.run().await,
            Commands::Fuzz(cmd) => cmd.run().await,
            Commands::Ci(cmd) => cmd.run().await,
            Commands::Plugin(cmd) => cmd.run().await,
            Commands::Config(cmd) => cmd.run().await,
        }
    }
}
