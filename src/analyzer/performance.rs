use chrono::DateTime;
use chrono::Utc;

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub throughput_bps: f64,
    pub throughput_pps: f64,
    pub latency_rtt: f64,
    pub jitter: f64,
    pub packet_loss_rate: f64,
    pub connection_establishment_time: f64,
}

pub struct PerformanceAnalyzer {
    metrics: Vec<(DateTime<Utc>, PerformanceMetrics)>,
}

impl PerformanceAnalyzer {
    pub fn new() -> Self {
        Self {
            metrics: vec![],
        }
    }

    pub fn record_metric(&mut self, metric: PerformanceMetrics) {
        self.metrics.push((Utc::now(), metric));
    }

    pub fn get_statistics(&self) -> PerformanceStatistics {
        // TODO: Calculate statistics
        PerformanceStatistics {
            avg_throughput_bps: 0.0,
            avg_latency_rtt: 0.0,
            max_jitter: 0.0,
            packet_loss_rate: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerformanceStatistics {
    pub avg_throughput_bps: f64,
    pub avg_latency_rtt: f64,
    pub max_jitter: f64,
    pub packet_loss_rate: f64,
}

impl Default for PerformanceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
