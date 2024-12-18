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
use std::str::FromStr;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

const ICMP_HEADER_SIZE: usize = 8;
const ICMP_PAYLOAD_SIZE: usize = 32;
const BUFFER_SIZE: usize = ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE;

#[derive(Debug)]
#[napi(object)]
struct TraceOption {
    pub max_hops: u32,
    pub timeout: u32,
    #[napi(ts_type = "'v4' | 'v6' | 'auto'")]
    pub ip_version: Option<String>,
}

#[derive(Debug)]
struct TraceTask {
    target: String,
    option: TraceOption,
}

#[derive(Debug, Clone)]
#[napi(object)]
struct HopResult {
    pub hop: u32,
    pub addr: Option<String>,
    pub rtt: Vec<f64>,
}

impl Task for TraceTask {
    type Output = Vec<HopResult>;
    type JsValue = Vec<HopResult>;

    fn compute(&mut self) -> Result<Self::Output> {
        let preferred_ip_version = self.option.ip_version.as_deref().unwrap_or("auto");
        let dest_addr = match IpAddr::from_str(&self.target) {
            Ok(ip) => ip,
            Err(_) => {
                // 如果不是有效的 IP 地址，尝试进行 DNS 解析
                let addrs: Vec<_> = (self.target.clone(), 0)
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
        let mut finished = false;
        let socket =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to create socket: {}", e),
                )
            })?;

        socket
            .set_read_timeout(Some(Duration::from_millis(self.option.timeout as u64)))
            .map_err(|e| Error::from_reason(format!("Failed to set read timeout: {}", e)))?;

        let dest = SocketAddr::new(IpAddr::V4(dest_ip), 0);

        let mut results = Vec::new();

        'finish: for ttl in 1..=self.option.max_hops {
            if finished {
                break;
            }

            // TODO: OS will kill send if ttl is too small
            socket.set_ttl(ttl).map_err(|e| {
                Error::new(Status::GenericFailure, format!("Failed to set TTL: {}", e))
            })?;

            let mut res = HopResult {
                hop: ttl,
                addr: None,
                rtt: Vec::new(),
            };

            for _ in 0..3 {
                let start_time = Instant::now();

                // 创建 ICMP Echo 请求包
                let mut icmp_buffer = [0u8; BUFFER_SIZE];
                let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
                icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                icmp_packet.set_icmp_code(IcmpCode::new(0));

                icmp_packet.set_sequence_number(ttl as u16);
                icmp_packet.set_identifier(std::process::id() as u16);

                let checksum =
                    pnet::packet::icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
                icmp_packet.set_checksum(checksum);

                socket
                    .send_to(icmp_packet.packet(), &dest.into())
                    .map_err(|e| {
                        Error::new(
                            Status::GenericFailure,
                            format!("Failed to send packet: {}", e),
                        )
                    })?;

                // 接收 ICMP Echo 回复
                let mut recv_buffer = buffer::UninitBuffer::new(2048);

                match socket.recv_from(recv_buffer.as_mut_slice()) {
                    Ok((size, src_addr)) => {
                        if let Some(ipv4_packet) =
                            Ipv4Packet::new(recv_buffer.as_mut_slice_initialized(size))
                        {
                            let icmp_payload = ipv4_packet.payload();

                            if let Some(icmp) = IcmpPacket::new(icmp_payload) {
                                match icmp.get_icmp_type() {
                                    IcmpTypes::EchoReply => {
                                        finished = true;
                                        break 'finish;
                                    }
                                    IcmpTypes::TimeExceeded => {
                                        let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                                        res.rtt.push(rtt);
                                        res.addr = Some(
                                            src_addr.as_socket_ipv4().unwrap().ip().to_string(),
                                        );
                                        continue;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
            results.push(res.clone());
        }

        Ok(results)
    }

    fn trace_ipv6(&self, dest_ip: Ipv6Addr) -> Result<Vec<HopResult>> {
        let mut finished = false;
        let socket =
            Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to create socket: {}", e),
                )
            })?;

        socket
            .set_read_timeout(Some(Duration::from_millis(self.option.timeout as u64)))
            .map_err(|e| Error::from_reason(format!("Failed to set read timeout: {}", e)))?;

        let dest = SocketAddr::new(IpAddr::V6(dest_ip), 0);

        let mut results = Vec::new();

        'finish: for ttl in 1..=self.option.max_hops {
            if finished {
                break;
            }
            socket.set_unicast_hops_v6(ttl).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to set hop limit: {}", e),
                )
            })?;

            let mut res = HopResult {
                hop: ttl,
                addr: None,
                rtt: Vec::new(),
            };

            for _ in 0..3 {
                let start_time = Instant::now();

                // 创建 ICMPv6 Echo 请求包
                let mut icmp_buffer = [0u8; BUFFER_SIZE];
                let mut packet = Ipv6MutableEchoRequestPacket::new(&mut icmp_buffer)
                    .ok_or_else(|| Error::from_reason("Failed to create ICMPv6 packet"))?;

                packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                packet.set_icmpv6_code(Icmpv6Code::new(0));
                packet.set_sequence_number(ttl as u16);
                packet.set_identifier(std::process::id() as u16);

                socket.send_to(packet.packet(), &dest.into()).map_err(|e| {
                    Error::new(
                        Status::GenericFailure,
                        format!("Failed to send packet: {}", e),
                    )
                })?;

                // 接收 ICMPv6 Echo 回复
                let mut recv_buffer = buffer::UninitBuffer::new(2048);

                match socket.recv_from(recv_buffer.as_mut_slice()) {
                    Ok((size, src_addr)) => {
                        if let Some(ipv6_packet) =
                            Ipv6Packet::new(recv_buffer.as_mut_slice_initialized(size))
                        {
                            let payload = ipv6_packet.payload();
                            if let Some(icmp) = Icmpv6Packet::new(payload) {
                                match icmp.get_icmpv6_type() {
                                    Icmpv6Types::EchoReply => {
                                        finished = true;
                                        break 'finish;
                                    }
                                    Icmpv6Types::TimeExceeded => {
                                        let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                                        res.rtt.push(rtt);
                                        res.addr = Some(
                                            src_addr.as_socket_ipv6().unwrap().ip().to_string(),
                                        );
                                        continue;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
            results.push(res.clone());
        }

        Ok(results)
    }
}

#[allow(unused)]
#[napi(ts_return_type = "Promise<HopResult[]>")]
fn trace_route(target: String, options: Option<TraceOption>) -> AsyncTask<TraceTask> {
    let option = options.unwrap_or(TraceOption {
        max_hops: 30,
        timeout: 1000,
        ip_version: None,
    });

    AsyncTask::new(TraceTask { target, option })
}
