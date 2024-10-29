use napi_derive_ohos::napi;
use napi_ohos::{bindgen_prelude::*, Task};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as Ipv6MutableEchoRequestPacket;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::Ipv6Addr;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

const ICMP_HEADER_SIZE: usize = 8;
const ICMP_PAYLOAD_SIZE: usize = 32;
const BUFFER_SIZE: usize = ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE;

#[derive(Debug)]
struct TraceTask {
    target: String,
    max_hops: u32,
}

#[derive(Debug)]
#[napi(object)]
struct HopResult {
    pub hop: u32,
    pub addr: Option<String>,
    pub rtt: f64,
}

impl Task for TraceTask {
    type Output = Vec<HopResult>;
    type JsValue = Vec<HopResult>;

    fn compute(&mut self) -> Result<Self::Output> {
        let dest_addr = self
            .target
            .parse::<IpAddr>()
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid IP address: {}", e)))?;

        match dest_addr {
            IpAddr::V4(ipv4) => self.trace_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.trace_ipv6(ipv6),
        }
    }

    fn resolve(&mut self, _: Env, output: Vec<HopResult>) -> Result<Self::JsValue> {
        Ok(output)
    }

    fn reject(&mut self, _: Env, err: Error) -> Result<Self::JsValue> {
        Err(err)
    }
}

impl TraceTask {
    fn trace_ipv4(&self, dest_ip: Ipv4Addr) -> Result<Vec<HopResult>> {
        let socket =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to create socket: {}", e),
                )
            })?;

        socket.set_nonblocking(true).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to set nonblocking: {}", e),
            )
        })?;

        let mut results = Vec::new();

        for ttl in 1..=self.max_hops {
            socket.set_ttl(ttl).map_err(|e| {
                Error::new(Status::GenericFailure, format!("Failed to set TTL: {}", e))
            })?;

            let start_time = Instant::now();

            // 创建 ICMP Echo 请求包
            let mut icmp_buffer = [0u8; BUFFER_SIZE];
            let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_packet.set_icmp_code(IcmpCode::new(0));

            icmp_packet.set_sequence_number(ttl as u16);
            icmp_packet.set_identifier(std::process::id() as u16);

            let dest = SocketAddr::new(IpAddr::V4(dest_ip), 0);
            socket
                .send_to(icmp_packet.packet(), &dest.into())
                .map_err(|e| {
                    Error::new(
                        Status::GenericFailure,
                        format!("Failed to send packet: {}", e),
                    )
                })?;

            // 接收 ICMP Echo 回复
            let mut recv_buffer = buffer::UninitBuffer::new(1024);
            let timeout = Duration::from_secs(1);
            let start = Instant::now();
            let mut addr = None;

            while start.elapsed() < timeout {
                match socket.recv_from(recv_buffer.as_mut_slice()) {
                    Ok((size, src_addr)) => {
                        if let Some(ipv4_packet) =
                            Ipv4Packet::new(recv_buffer.as_mut_slice_initialized(size))
                        {
                            let icmp_payload = ipv4_packet.payload();

                            if let Some(icmp) = IcmpPacket::new(icmp_payload) {
                                if icmp.get_icmp_type() == IcmpTypes::EchoReply {
                                    let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                                    addr =
                                        Some(src_addr.as_socket_ipv4().unwrap().ip().to_string());
                                    results.push(HopResult {
                                        hop: ttl,
                                        addr: Some(
                                            src_addr.as_socket_ipv4().unwrap().ip().to_string(),
                                        ),
                                        rtt,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => continue,
                }
            }

            if addr.is_none() {
                results.push(HopResult {
                    hop: ttl,
                    addr: None,
                    rtt: -1.0,
                });
            }

            if let Some(ref addr) = addr {
                if addr == &dest_ip.to_string() {
                    break;
                }
            }
        }

        Ok(results)
    }
    fn trace_ipv6(&self, dest_ip: Ipv6Addr) -> Result<Vec<HopResult>> {
        let socket =
            Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to create socket: {}", e),
                )
            })?;

        socket.set_nonblocking(true).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to set nonblocking: {}", e),
            )
        })?;

        let mut results = Vec::new();

        for ttl in 1..=self.max_hops {
            socket.set_unicast_hops_v6(ttl).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to set hop limit: {}", e),
                )
            })?;

            let start_time = Instant::now();

            // 创建 ICMPv6 Echo 请求包
            let mut icmp_buffer = [0u8; BUFFER_SIZE];
            let mut packet = Ipv6MutableEchoRequestPacket::new(&mut icmp_buffer)
                .ok_or_else(|| Error::from_reason("Failed to create ICMPv6 packet"))?;

            packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
            packet.set_icmpv6_code(Icmpv6Code::new(0));
            packet.set_sequence_number(ttl as u16);
            packet.set_identifier(std::process::id() as u16);

            let dest = SocketAddr::new(IpAddr::V6(dest_ip), 0);
            socket.send_to(packet.packet(), &dest.into()).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to send packet: {}", e),
                )
            })?;

            // 接收 ICMPv6 Echo 回复
            let mut recv_buffer = buffer::UninitBuffer::new(1024);
            let timeout = Duration::from_secs(1);
            let start = Instant::now();
            let mut addr = None;

            while start.elapsed() < timeout {
                match socket.recv_from(recv_buffer.as_mut_slice()) {
                    Ok((size, src_addr)) => {
                        if let Some(ipv6_packet) =
                            Ipv6Packet::new(recv_buffer.as_mut_slice_initialized(size))
                        {
                            let payload = ipv6_packet.payload();
                            if let Some(icmp) = Icmpv6Packet::new(payload) {
                                if icmp.get_icmpv6_type() == Icmpv6Types::EchoReply {
                                    let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                                    addr =
                                        Some(src_addr.as_socket_ipv6().unwrap().ip().to_string());
                                    results.push(HopResult {
                                        hop: ttl,
                                        addr: Some(
                                            src_addr.as_socket_ipv6().unwrap().ip().to_string(),
                                        ),
                                        rtt,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => continue,
                }
            }

            if addr.is_none() {
                results.push(HopResult {
                    hop: ttl,
                    addr: None,
                    rtt: -1.0,
                });
            }

            if let Some(ref addr) = addr {
                if addr == &dest_ip.to_string() {
                    break;
                }
            }
        }

        Ok(results)
    }
}

#[allow(unused)]
#[napi]
fn trace_route(target: String, max_hops: Option<u32>) -> AsyncTask<TraceTask> {
    let task = TraceTask {
        target,
        max_hops: max_hops.unwrap_or(30),
    };

    AsyncTask::new(task)
}
