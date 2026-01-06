use std::net::{SocketAddr, IpAddr};
use anyhow::{Result, Context};

/// Parse address string in format "IP:port" or "[IPv6]:port"
pub fn parse_address(addr_str: &str) -> Result<SocketAddr> {
    // Handle IPv6 format [::1]:8080
    if addr_str.starts_with('[') {
        if let Some(close_bracket) = addr_str.find(']') {
            let ip_str = &addr_str[1..close_bracket];
            let port_str = &addr_str[close_bracket + 1..];
            
            if !port_str.starts_with(':') {
                return Err(anyhow::anyhow!("Invalid IPv6 address format: {}", addr_str));
            }
            
            let port: u16 = port_str[1..].parse()
                .context(format!("Invalid port in address: {}", addr_str))?;
            
            let ip: IpAddr = ip_str.parse()
                .context(format!("Invalid IPv6 address: {}", ip_str))?;
            
            return Ok(SocketAddr::new(ip, port));
        }
    }
    
    // Handle IPv4 format 192.168.1.1:8080 or IPv6 format ::1:8080
    addr_str.parse()
        .context(format!("Failed to parse address: {}", addr_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let addr = parse_address("192.168.1.1:8080").unwrap();
        assert_eq!(addr.ip(), IpAddr::from([192, 168, 1, 1]));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_parse_ipv6() {
        let addr = parse_address("[::1]:8080").unwrap();
        assert_eq!(addr.port(), 8080);
    }
}
