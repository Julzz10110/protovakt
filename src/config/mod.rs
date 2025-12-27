mod schema;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub use schema::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: String,
    pub general: GeneralConfig,
    pub analysis: Option<AnalysisConfig>,
    pub fuzzing: Option<FuzzingConfig>,
    pub reporting: Option<ReportingConfig>,
    pub ci: Option<CiConfig>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            general: GeneralConfig::default(),
            analysis: Some(AnalysisConfig::default()),
            fuzzing: Some(FuzzingConfig::default()),
            reporting: Some(ReportingConfig::default()),
            ci: Some(CiConfig::default()),
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
