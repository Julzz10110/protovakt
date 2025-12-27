use anyhow::Result;
use clap::{Args, Subcommand};
use tracing::info;

use crate::config::Config;

#[derive(Args)]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Validate configuration file
    Validate {
        /// Config file path
        #[arg(default_value = ".protovakt.yml")]
        file: String,
    },
    /// Show current configuration
    Show {
        /// Config file path
        #[arg(default_value = ".protovakt.yml")]
        file: String,
    },
    /// Generate example configuration
    Generate {
        /// Output file
        #[arg(default_value = ".protovakt.yml")]
        output: String,
    },
}

impl ConfigCommand {
    pub async fn run(self) -> Result<()> {
        match self.action {
            ConfigAction::Validate { file } => {
                info!("Validating config file: {}", file);
                match Config::load(&file) {
                    Ok(config) => {
                        println!("✓ Configuration file is valid");
                        println!("Version: {}", config.version);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("✗ Configuration file is invalid: {}", e);
                        Err(e)
                    }
                }
            }
            ConfigAction::Show { file } => {
                info!("Showing configuration from: {}", file);
                match Config::load(&file) {
                    Ok(config) => {
                        println!("{}", serde_yaml::to_string(&config)?);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error loading config: {}", e);
                        Err(e)
                    }
                }
            }
            ConfigAction::Generate { output } => {
                info!("Generating example config to: {}", output);
                let config = Config::default();
                config.save(&output)?;
                println!("✓ Example configuration generated: {}", output);
                Ok(())
            }
        }
    }
}
