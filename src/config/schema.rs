use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub log_level: String,
    pub output_dir: String,
    pub temp_dir: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            output_dir: "./reports".to_string(),
            temp_dir: "/tmp/protovakt".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub enabled_protocols: Vec<String>,
    pub compliance: ComplianceConfig,
    pub performance: PerformanceConfig,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enabled_protocols: vec!["quic".to_string(), "http3".to_string(), "grpc".to_string()],
            compliance: ComplianceConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub rfc_strict: bool,
    pub security_checks: bool,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            rfc_strict: true,
            security_checks: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub metrics: Vec<String>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            metrics: vec!["throughput".to_string(), "latency".to_string(), "jitter".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingConfig {
    pub targets: Vec<FuzzTarget>,
    pub strategies: Vec<FuzzingStrategy>,
    pub limits: FuzzingLimits,
}

impl Default for FuzzingConfig {
    fn default() -> Self {
        Self {
            targets: vec![],
            strategies: vec![
                FuzzingStrategy {
                    strategy_type: "stateful".to_string(),
                    max_depth: Some(15),
                    corpus: None,
                }
            ],
            limits: FuzzingLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTarget {
    pub name: String,
    pub endpoint: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingStrategy {
    #[serde(rename = "type")]
    pub strategy_type: String,
    pub max_depth: Option<u32>,
    pub corpus: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingLimits {
    pub duration: String,
    pub memory_mb: u64,
    pub requests_per_sec: u64,
    pub cpu_cores: u32,
}

impl Default for FuzzingLimits {
    fn default() -> Self {
        Self {
            duration: "8h".to_string(),
            memory_mb: 4096,
            requests_per_sec: 1000,
            cpu_cores: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    pub formats: Vec<String>,
    pub notifications: Option<NotificationConfig>,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            formats: vec!["json".to_string(), "html".to_string()],
            notifications: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub slack: Option<SlackConfig>,
    pub email: Option<EmailConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiConfig {
    pub quality_gates: QualityGates,
}

impl Default for CiConfig {
    fn default() -> Self {
        Self {
            quality_gates: QualityGates::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGates {
    pub security_critical: u32,
    pub security_high: u32,
    pub coverage_min: f64,
    pub performance_regression: f64,
}

impl Default for QualityGates {
    fn default() -> Self {
        Self {
            security_critical: 0,
            security_high: 5,
            coverage_min: 0.85,
            performance_regression: 0.10,
        }
    }
}
