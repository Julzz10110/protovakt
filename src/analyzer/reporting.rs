use anyhow::Result;
use std::path::Path;
use serde::Serialize;
use chrono::Utc;

use crate::analyzer::engine::AnalysisStatistics;
use crate::core::Finding;

#[derive(Debug, Serialize)]
pub struct Report {
    pub timestamp: String,
    pub summary: ReportSummary,
    pub findings: Vec<FindingReport>,
    pub protocols: Vec<ProtocolStats>,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub total_packets: u64,
    pub processed_packets: u64,
    pub total_findings: usize,
    pub findings_by_severity: SeverityCounts,
}

#[derive(Debug, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Serialize)]
pub struct FindingReport {
    pub severity: String,
    pub category: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ProtocolStats {
    pub protocol: String,
    pub packet_count: u64,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_json(&self, stats: &AnalysisStatistics) -> Result<String> {
        let report = self.build_report(stats);
        Ok(serde_json::to_string_pretty(&report)?)
    }

    pub fn generate_html(&self, stats: &AnalysisStatistics) -> Result<String> {
        let report = self.build_report(stats);
        let json_data = serde_json::to_string(&report)?;
        
        Ok(format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>protovakt Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .severity-critical {{ color: #d32f2f; }}
        .severity-high {{ color: #f57c00; }}
        .severity-medium {{ color: #fbc02d; }}
        .severity-low {{ color: #388e3c; }}
        .severity-info {{ color: #1976d2; }}
        .findings {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .finding {{
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid;
            background: #f9f9f9;
        }}
        .finding.critical {{ border-color: #d32f2f; }}
        .finding.high {{ border-color: #f57c00; }}
        .finding.medium {{ border-color: #fbc02d; }}
        .finding.low {{ border-color: #388e3c; }}
        .finding.info {{ border-color: #1976d2; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }}
        .finding-severity {{
            font-weight: bold;
            text-transform: uppercase;
        }}
        .finding-category {{
            color: #666;
            font-size: 0.9em;
        }}
        .protocols {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f5f5f5;
            font-weight: 600;
        }}
        .footer {{
            text-align: center;
            color: #666;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 protovakt Analysis Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Packets</h3>
            <div class="value">{total_packets}</div>
        </div>
        <div class="summary-card">
            <h3>Processed</h3>
            <div class="value">{processed_packets}</div>
        </div>
        <div class="summary-card">
            <h3>Findings</h3>
            <div class="value">{total_findings}</div>
        </div>
        <div class="summary-card">
            <h3>Protocols</h3>
            <div class="value">{protocol_count}</div>
        </div>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Critical</h3>
            <div class="value severity-critical">{critical}</div>
        </div>
        <div class="summary-card">
            <h3>High</h3>
            <div class="value severity-high">{high}</div>
        </div>
        <div class="summary-card">
            <h3>Medium</h3>
            <div class="value severity-medium">{medium}</div>
        </div>
        <div class="summary-card">
            <h3>Low</h3>
            <div class="value severity-low">{low}</div>
        </div>
        <div class="summary-card">
            <h3>Info</h3>
            <div class="value severity-info">{info}</div>
        </div>
    </div>
    
    <div class="findings">
        <h2>Findings</h2>
        {findings_html}
    </div>
    
    <div class="protocols">
        <h2>Protocol Statistics</h2>
        <table>
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Packet Count</th>
                </tr>
            </thead>
            <tbody>
                {protocols_html}
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>Generated by protovakt - Protocol Analysis and Fuzzing System</p>
    </div>
    
    <script>
        const reportData = {json_data};
        console.log('Report data:', reportData);
    </script>
</body>
</html>"#,
            timestamp = report.timestamp,
            total_packets = report.summary.total_packets,
            processed_packets = report.summary.processed_packets,
            total_findings = report.summary.total_findings,
            protocol_count = report.protocols.len(),
            critical = report.summary.findings_by_severity.critical,
            high = report.summary.findings_by_severity.high,
            medium = report.summary.findings_by_severity.medium,
            low = report.summary.findings_by_severity.low,
            info = report.summary.findings_by_severity.info,
            findings_html = self.generate_findings_html(&report.findings),
            protocols_html = self.generate_protocols_html(&report.protocols),
            json_data = json_data
        ))
    }

    pub fn save_report<P: AsRef<Path>>(
        &self,
        stats: &AnalysisStatistics,
        output_dir: P,
        formats: &[String],
    ) -> Result<Vec<String>> {
        let output_path = output_dir.as_ref();
        std::fs::create_dir_all(output_path)?;
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let mut saved_files = Vec::new();
        
        for format in formats {
            match format.to_lowercase().as_str() {
                "json" => {
                    let json_content = self.generate_json(stats)?;
                    let json_path = output_path.join(format!("report_{}.json", timestamp));
                    std::fs::write(&json_path, json_content)?;
                    saved_files.push(json_path.to_string_lossy().to_string());
                }
                "html" => {
                    let html_content = self.generate_html(stats)?;
                    let html_path = output_path.join(format!("report_{}.html", timestamp));
                    std::fs::write(&html_path, html_content)?;
                    saved_files.push(html_path.to_string_lossy().to_string());
                }
                _ => {
                    tracing::warn!("Unknown report format: {}", format);
                }
            }
        }
        
        Ok(saved_files)
    }

    fn build_report(&self, stats: &AnalysisStatistics) -> Report {
        let mut severity_counts = SeverityCounts {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        let findings: Vec<FindingReport> = stats.findings.iter().map(|f| {
            match f.severity {
                crate::core::Severity::Critical => severity_counts.critical += 1,
                crate::core::Severity::High => severity_counts.high += 1,
                crate::core::Severity::Medium => severity_counts.medium += 1,
                crate::core::Severity::Low => severity_counts.low += 1,
                crate::core::Severity::Info => severity_counts.info += 1,
            }
            
            FindingReport {
                severity: format!("{:?}", f.severity),
                category: f.category.clone(),
                message: f.message.clone(),
                details: f.details.clone(),
            }
        }).collect();

        let protocols: Vec<ProtocolStats> = stats.protocols_found.iter()
            .map(|(protocol, count)| ProtocolStats {
                protocol: protocol.clone(),
                packet_count: *count,
            })
            .collect();

        Report {
            timestamp: Utc::now().to_rfc3339(),
            summary: ReportSummary {
                total_packets: stats.total_packets,
                processed_packets: stats.processed_packets,
                total_findings: stats.findings.len(),
                findings_by_severity: severity_counts,
            },
            findings,
            protocols,
        }
    }

    fn generate_findings_html(&self, findings: &[FindingReport]) -> String {
        if findings.is_empty() {
            return "<p>No findings detected.</p>".to_string();
        }

        findings.iter().map(|f| {
            format!(
                r#"<div class="finding {severity}">
                    <div class="finding-header">
                        <span class="finding-severity severity-{severity}">{severity}</span>
                        <span class="finding-category">{category}</span>
                    </div>
                    <div class="finding-message">{message}</div>
                    {details}
                </div>"#,
                severity = f.severity.to_lowercase(),
                category = html_escape(&f.category),
                message = html_escape(&f.message),
                details = if let Some(ref d) = f.details {
                    format!("<pre>{}</pre>", html_escape(&serde_json::to_string_pretty(d).unwrap_or_default()))
                } else {
                    String::new()
                }
            )
        }).collect::<Vec<_>>().join("\n")
    }

    fn generate_protocols_html(&self, protocols: &[ProtocolStats]) -> String {
        if protocols.is_empty() {
            return "<tr><td colspan='2'>No protocols detected.</td></tr>".to_string();
        }

        protocols.iter().map(|p| {
            format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(&p.protocol),
                p.packet_count
            )
        }).collect::<Vec<_>>().join("\n")
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
