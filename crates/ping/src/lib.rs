use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{Duration, Instant};

use napi_derive_ohos::napi;
use napi_ohos::bindgen_prelude::*;
use napi_ohos::{Env, Task};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as Ipv6MutableEchoRequestPacket;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types};
use pnet::packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};

use buffer::UninitBuffer;

const ICMP_HEADER_SIZE: usize = 8;
const ICMP_PAYLOAD_SIZE: usize = 32;
const BUFFER_SIZE: usize = ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE;

#[derive(Debug)]
#[napi(object)]
pub struct PingResult {
    pub host: String,
    pub ip: String,
    pub sequence: u16,
    pub ttl: u32,
    pub rtt_ms: f64,
    pub success: bool,
    pub error: Option<String>,
    pub ip_version: u8,
}

#[derive(Debug)]
#[napi(object)]
pub struct PingOptions {
    pub count: u32,
    pub timeout: u32,
    pub interval: u32,
    #[napi(ts_type = "'v4' | 'v6' | 'auto'")]
    pub ip_version: Option<String>,
}

struct PingTask {
    host: String,
    options: PingOptions,
}

impl Task for PingTask {
    type Output = Vec<PingResult>;
    type JsValue = Vec<PingResult>;

    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        let preferred_ip_version = self.options.ip_version.as_deref().unwrap_or("auto");

        let ip_addr = match IpAddr::from_str(&self.host) {
            Ok(ip) => ip,
            Err(_) => {
                // 如果不是有效的 IP 地址，尝试进行 DNS 解析
                let addrs: Vec<_> = (self.host.clone(), 0)
                    .to_socket_addrs()
                    .map_err(|e| {
                        Error::from_reason(format!("Failed to resolve host: {}", e.to_string()))
                    })?
                    .map(|addr| addr.ip())
                    .collect();

                if addrs.is_empty() {
                    return Err(Error::from_reason("No IP address found for host"));
                }

                match preferred_ip_version {
                    "v4" => addrs.into_iter().find(|ip| ip.is_ipv4()),
                    "v6" => addrs.into_iter().find(|ip| ip.is_ipv6()),
                    _ => Some(addrs[0]),
                }
                .ok_or_else(|| {
                    Error::from_reason(format!(
                        "No {} address found for host",
                        preferred_ip_version
                    ))
                })?
            }
        };

        let mut results = Vec::new();

        match ip_addr {
            IpAddr::V4(ipv4) => {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
                    .map_err(|e| {
                        Error::from_reason(format!(
                            "Failed to create IPv4 socket: {}",
                            e.to_string()
                        ))
                    })?;

                socket
                    .set_read_timeout(Some(Duration::from_millis(self.options.timeout as u64)))
                    .map_err(|e| {
                        Error::from_reason(format!("Failed to set read timeout: {}", e))
                    })?;

                for sequence in 0..self.options.count {
                    let result = send_ping_v4(&socket, &self.host, ipv4, sequence as u16)?;
                    results.push(result);
                    std::thread::sleep(Duration::from_millis(self.options.interval as u64));
                }
            }
            IpAddr::V6(ipv6) => {
                let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))
                    .map_err(|e| {
                        Error::from_reason(format!("Failed to create IPv6 socket: {}", e))
                    })?;

                socket
                    .set_read_timeout(Some(Duration::from_millis(self.options.timeout as u64)))
                    .map_err(|e| {
                        Error::from_reason(format!("Failed to set read timeout: {}", e))
                    })?;

                for sequence in 0..self.options.count {
                    let result = send_ping_v6(&socket, &self.host, ipv6, sequence as u16)?;
                    results.push(result);
                    std::thread::sleep(Duration::from_millis(self.options.interval as u64));
                }
            }
        }

        Ok(results)
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> napi_ohos::Result<Self::JsValue> {
        Ok(output)
    }

    fn reject(&mut self, _: Env, err: Error) -> Result<Self::JsValue> {
        Err(err)
    }
}

fn send_ping_v4(
    socket: &Socket,
    host: &str,
    ip: std::net::Ipv4Addr,
    sequence: u16,
) -> napi_ohos::Result<PingResult> {
    let mut buf = vec![0; BUFFER_SIZE];
    let mut packet = MutableEchoRequestPacket::new(&mut buf)
        .ok_or_else(|| Error::from_reason("Failed to create ICMPv4 packet"))?;

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));
    packet.set_sequence_number(sequence);
    packet.set_identifier(std::process::id() as u16);

    let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(packet.packet()).unwrap());
    packet.set_checksum(checksum);

    let start = Instant::now();

    socket
        .send_to(
            packet.packet(),
            &std::net::SocketAddr::new(IpAddr::V4(ip), 0).into(),
        )
        .map_err(|e| Error::from_reason(format!("Failed to send packet: {}", e)))?;

    let mut recv_buf = UninitBuffer::new(2048);
    match socket.recv_from(recv_buf.as_mut_slice()) {
        Ok((_, _)) => {
            let duration = start.elapsed();
            let ttl = socket.ttl().unwrap_or(0);

            Ok(PingResult {
                host: host.to_string(),
                ip: ip.to_string(),
                sequence,
                ttl,
                rtt_ms: duration.as_secs_f64() * 1000.0,
                success: true,
                error: None,
                ip_version: 4,
            })
        }
        Err(e) => Ok(PingResult {
            host: host.to_string(),
            ip: ip.to_string(),
            sequence,
            ttl: 0,
            rtt_ms: 0.0,
            success: false,
            error: Some(e.to_string()),
            ip_version: 4,
        }),
    }
}

fn send_ping_v6(
    socket: &Socket,
    host: &str,
    ip: std::net::Ipv6Addr,
    sequence: u16,
) -> napi_ohos::Result<PingResult> {
    let mut buf = vec![0; BUFFER_SIZE];
    let mut packet = Ipv6MutableEchoRequestPacket::new(&mut buf)
        .ok_or_else(|| Error::from_reason("Failed to create ICMPv6 packet"))?;

    packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    packet.set_icmpv6_code(Icmpv6Code::new(0));
    packet.set_sequence_number(sequence);
    packet.set_identifier(std::process::id() as u16);

    // ICMPv6 校验和由内核自动计算
    let start = Instant::now();

    socket
        .send_to(
            packet.packet(),
            &std::net::SocketAddr::new(IpAddr::V6(ip), 0).into(),
        )
        .map_err(|e| Error::from_reason(format!("Failed to send packet: {}", e)))?;

    let mut recv_buf = UninitBuffer::new(2048);
    match socket.recv_from(recv_buf.as_mut_slice()) {
        Ok((_, _)) => {
            let duration = start.elapsed();
            let ttl = socket.ttl().unwrap_or(0);

            Ok(PingResult {
                host: host.to_string(),
                ip: ip.to_string(),
                sequence,
                ttl,
                rtt_ms: duration.as_secs_f64() * 1000.0,
                success: true,
                error: None,
                ip_version: 6,
            })
        }
        Err(e) => Ok(PingResult {
            host: host.to_string(),
            ip: ip.to_string(),
            sequence,
            ttl: 0,
            rtt_ms: 0.0,
            success: false,
            error: Some(e.to_string()),
            ip_version: 6,
        }),
    }
}

#[allow(unused)]
#[napi(ts_return_type = "Promise<PingResult[]>")]
fn ping_async(host: String, options: Option<PingOptions>) -> AsyncTask<PingTask> {
    let opts = options.unwrap_or(PingOptions {
        count: 4,
        timeout: 1000,
        interval: 1000,
        ip_version: None,
    });

    AsyncTask::new(PingTask {
        host,
        options: opts,
    })
}
