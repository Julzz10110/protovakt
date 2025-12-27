use anyhow::{Result, Context};
use std::time::Duration;

pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    
    if s.is_empty() {
        return Err(anyhow::anyhow!("Empty duration string"));
    }

    let (value, unit) = if let Some(pos) = s.rfind(|c: char| c.is_alphabetic()) {
        let (val_str, unit_str) = s.split_at(pos);
        let value: u64 = val_str.parse()
            .context("Invalid duration value")?;
        (value, unit_str)
    } else {
        return Err(anyhow::anyhow!("No unit specified in duration"));
    };

    let seconds = match unit.to_lowercase().as_str() {
        "s" | "sec" | "second" | "seconds" => value,
        "m" | "min" | "minute" | "minutes" => value * 60,
        "h" | "hr" | "hour" | "hours" => value * 3600,
        "d" | "day" | "days" => value * 86400,
        _ => return Err(anyhow::anyhow!("Unknown duration unit: {}", unit)),
    };

    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
    }
}
