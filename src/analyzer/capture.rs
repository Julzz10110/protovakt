use anyhow::{Result, Context};
use bytes::Bytes;
use pcap::{Capture, Packet};
use std::path::Path;
use tracing::{info, warn, error};

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    pub payload: Bytes,
}

pub struct PcapReader;

impl PcapReader {
    pub fn new() -> Self {
        Self
    }

    pub fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<PcapFileReader> {
        let path_ref = path.as_ref();
        info!("Opening PCAP file: {}", path_ref.display());
        
        let cap = Capture::from_file(path_ref)
            .context("Failed to open PCAP file")?;
        
        Ok(PcapFileReader { cap })
    }
}

pub struct PcapFileReader {
    cap: Capture<pcap::Offline>,
}

impl PcapFileReader {
    pub fn packet_count(&self) -> Option<usize> {
        // pcap crate doesn't provide direct packet count
        // We'll need to iterate to count
        None
    }

    pub fn next_packet(&mut self) -> Result<Option<PacketInfo>> {
        match self.cap.next_packet() {
            Ok(packet) => {
                let timestamp = chrono::DateTime::from_timestamp(
                    packet.header.ts.tv_sec as i64,
                    packet.header.ts.tv_usec as u32 * 1000,
                ).unwrap_or_else(chrono::Utc::now);

                // Parse Ethernet frame to get IP addresses
                // For MVP, we'll use a simplified approach
                let (source, destination, protocol, payload) = 
                    Self::parse_packet(&packet)?;

                Ok(Some(PacketInfo {
                    timestamp,
                    source,
                    destination,
                    protocol,
                    length: packet.header.len as usize,
                    payload: Bytes::from(packet.data.to_vec()),
                }))
            }
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => {
                error!("Error reading packet: {}", e);
                Err(anyhow::anyhow!("PCAP read error: {}", e))
            }
        }
    }

    fn parse_packet(packet: &Packet) -> Result<(String, String, String, Vec<u8>)> {
        // Basic packet parsing using pnet
        use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::ipv6::Ipv6Packet;
        use pnet::packet::tcp::TcpPacket;
        use pnet::packet::udp::UdpPacket;
        use pnet::packet::Packet as PnetPacket;

        let data = packet.data;
        
        // Try to parse as Ethernet frame
        if let Some(ethernet) = EthernetPacket::new(data) {
            let source = format!("{}", ethernet.get_source());
            let destination = format!("{}", ethernet.get_destination());
            
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let src_ip = ipv4.get_source();
                        let dst_ip = ipv4.get_destination();
                        
                        // Determine transport protocol
                        let (protocol, payload) = match ipv4.get_next_level_protocol() {
                            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                    ("TCP".to_string(), tcp.payload().to_vec())
                                } else {
                                    ("TCP".to_string(), ipv4.payload().to_vec())
                                }
                            }
                            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                    ("UDP".to_string(), udp.payload().to_vec())
                                } else {
                                    ("UDP".to_string(), ipv4.payload().to_vec())
                                }
                            }
                            _ => ("Unknown".to_string(), ipv4.payload().to_vec()),
                        };
                        
                        return Ok((
                            format!("{}:{}", src_ip, "?"),
                            format!("{}:{}", dst_ip, "?"),
                            protocol,
                            payload,
                        ));
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                        let src_ip = ipv6.get_source();
                        let dst_ip = ipv6.get_destination();
                        return Ok((
                            format!("{}", src_ip),
                            format!("{}", dst_ip),
                            "IPv6".to_string(),
                            ipv6.payload().to_vec(),
                        ));
                    }
                }
                _ => {}
            }
            
            return Ok((
                source,
                destination,
                "Ethernet".to_string(),
                ethernet.payload().to_vec(),
            ));
        }

        // Fallback: raw packet
        Ok((
            "unknown".to_string(),
            "unknown".to_string(),
            "Raw".to_string(),
            data.to_vec(),
        ))
    }
}

impl Default for PcapReader {
    fn default() -> Self {
        Self::new()
    }
}
