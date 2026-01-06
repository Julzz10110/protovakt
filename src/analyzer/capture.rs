use anyhow::{Result, Context};
use bytes::Bytes;
use pcap::{Capture, Packet};
use std::path::Path;
use tracing::{info, error};

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

    pub fn open_live(&self, interface: &str, filter: Option<&str>) -> Result<PcapLiveReader> {
        info!("Opening live capture on interface: {}", interface);
        
        // Try to open the device
        let mut cap = Capture::from_device(interface)
            .context(format!("Failed to open device: {}", interface))?
            .promisc(true)
            .snaplen(65535)
            .timeout(100) // 100ms timeout for non-blocking reads
            .open()
            .context("Failed to activate capture")?;

        // Apply BPF filter if provided
        if let Some(filter_expr) = filter {
            info!("Applying BPF filter: {}", filter_expr);
            cap.filter(filter_expr, true)
                .context(format!("Failed to apply filter: {}", filter_expr))?;
        }
        
        Ok(PcapLiveReader { cap })
    }

    pub fn list_devices(&self) -> Result<Vec<String>> {
        let devices = pcap::Device::list()
            .context("Failed to list network devices")?;
        
        Ok(devices.iter()
            .map(|d| d.name.clone())
            .collect())
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

    pub fn parse_packet(packet: &Packet) -> Result<(String, String, String, Vec<u8>)> {
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
                        let (src_addr, dst_addr, protocol, payload) = match ipv4.get_next_level_protocol() {
                            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                    let src_port = tcp.get_source();
                                    let dst_port = tcp.get_destination();
                                    (
                                        format!("{}:{}", src_ip, src_port),
                                        format!("{}:{}", dst_ip, dst_port),
                                        "TCP".to_string(),
                                        tcp.payload().to_vec()
                                    )
                                } else {
                                    (
                                        format!("{}:?", src_ip),
                                        format!("{}:?", dst_ip),
                                        "TCP".to_string(),
                                        ipv4.payload().to_vec()
                                    )
                                }
                            }
                            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                    let src_port = udp.get_source();
                                    let dst_port = udp.get_destination();
                                    (
                                        format!("{}:{}", src_ip, src_port),
                                        format!("{}:{}", dst_ip, dst_port),
                                        "UDP".to_string(),
                                        udp.payload().to_vec()
                                    )
                                } else {
                                    (
                                        format!("{}:?", src_ip),
                                        format!("{}:?", dst_ip),
                                        "UDP".to_string(),
                                        ipv4.payload().to_vec()
                                    )
                                }
                            }
                            _ => (
                                format!("{}:?", src_ip),
                                format!("{}:?", dst_ip),
                                "Unknown".to_string(),
                                ipv4.payload().to_vec()
                            ),
                        };
                        
                        return Ok((src_addr, dst_addr, protocol, payload));
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                        let src_ip = ipv6.get_source();
                        let dst_ip = ipv6.get_destination();
                        
                        // Determine transport protocol for IPv6
                        // IPv6 uses the same next header values as IPv4
                        let next_header = ipv6.get_next_header();
                        let (src_addr, dst_addr, protocol, payload) = 
                            if next_header == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                    let src_port = tcp.get_source();
                                    let dst_port = tcp.get_destination();
                                    (
                                        format!("[{}]:{}", src_ip, src_port),
                                        format!("[{}]:{}", dst_ip, dst_port),
                                        "TCP".to_string(),
                                        tcp.payload().to_vec()
                                    )
                                } else {
                                    (
                                        format!("[{}]:?", src_ip),
                                        format!("[{}]:?", dst_ip),
                                        "TCP".to_string(),
                                        ipv6.payload().to_vec()
                                    )
                                }
                            } else if next_header == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                                if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                    let src_port = udp.get_source();
                                    let dst_port = udp.get_destination();
                                    (
                                        format!("[{}]:{}", src_ip, src_port),
                                        format!("[{}]:{}", dst_ip, dst_port),
                                        "UDP".to_string(),
                                        udp.payload().to_vec()
                                    )
                                } else {
                                    (
                                        format!("[{}]:?", src_ip),
                                        format!("[{}]:?", dst_ip),
                                        "UDP".to_string(),
                                        ipv6.payload().to_vec()
                                    )
                                }
                            } else {
                                (
                                    format!("{}", src_ip),
                                    format!("{}", dst_ip),
                                    "IPv6".to_string(),
                                    ipv6.payload().to_vec(),
                                )
                            };
                        
                        return Ok((src_addr, dst_addr, protocol, payload));
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

pub struct PcapLiveReader {
    cap: Capture<pcap::Active>,
}

impl PcapLiveReader {
    pub fn next_packet(&mut self) -> Result<Option<PacketInfo>> {
        match self.cap.next_packet() {
            Ok(packet) => {
                let timestamp = chrono::DateTime::from_timestamp(
                    packet.header.ts.tv_sec as i64,
                    packet.header.ts.tv_usec as u32 * 1000,
                ).unwrap_or_else(chrono::Utc::now);

                // Parse Ethernet frame to get IP addresses
                let (source, destination, protocol, payload) = 
                    PcapFileReader::parse_packet(&packet)?;

                Ok(Some(PacketInfo {
                    timestamp,
                    source,
                    destination,
                    protocol,
                    length: packet.header.len as usize,
                    payload: Bytes::from(packet.data.to_vec()),
                }))
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is normal for live capture, return None to allow checking
                Ok(None)
            }
            Err(e) => {
                error!("Error reading packet: {}", e);
                Err(anyhow::anyhow!("PCAP read error: {}", e))
            }
        }
    }
}

impl Default for PcapReader {
    fn default() -> Self {
        Self::new()
    }
}
