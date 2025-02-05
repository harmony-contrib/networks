#![allow(unused_assignments)]

use napi_derive_ohos::napi;
use napi_ohos::{bindgen_prelude::*, Task};
use nix::sys::{
    socket::{
        recvfrom, recvmsg, sendto, setsockopt, socket, sockopt, AddressFamily, ControlMessageOwned,
        MsgFlags, SockFlag, SockProtocol, SockType, SockaddrIn, SockaddrIn6,
    },
    time::TimeVal,
};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpType, IcmpTypes};
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as Ipv6MutableEchoRequestPacket;
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::{io::IoSliceMut, net::SocketAddrV6};
use std::{
    net::{Ipv4Addr, ToSocketAddrs},
    time::Instant,
};

const ICMP_HEADER_SIZE: usize = 8;
const ICMP_PAYLOAD_SIZE: usize = 32;
const BUFFER_SIZE: usize = ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE;

#[derive(Debug)]
#[napi(object)]
struct TraceOption {
    /// Max hops
    /// @default 64
    pub max_hops: i32,
    /// Timeout
    /// @default 1
    /// @unit second
    pub timeout: i32,
    #[napi(ts_type = "'v4' | 'v6' | 'auto'")]
    pub ip_version: Option<String>,
    /// Retry times every hops
    /// @default 3
    pub re_try: Option<i32>,
}

#[derive(Debug)]
struct TraceTask {
    target: String,
    option: TraceOption,
}

#[derive(Debug, Clone)]
#[napi(object)]
struct HopResult {
    /// hop index
    pub hop: i32,
    /// current hop's target ip address
    pub addr: Option<String>,
    /// rtt
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

        let socket_instance = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Icmp,
        )
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create socket: {}", e),
            )
        })?;

        let timeout = TimeVal::new(self.option.timeout.into(), 0);
        setsockopt(&socket_instance, sockopt::ReceiveTimeout, &timeout).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to set read timeout: {}", e),
            )
        })?;

        // allow recvmsg when timeout
        setsockopt(&socket_instance, sockopt::Ipv4RecvErr, &true).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to set EQUEUE: {}", e),
            )
        })?;

        let dest = SockaddrIn::from(SocketAddrV4::new(dest_ip, 0));

        let mut results = Vec::new();

        'finish: for ttl in 1..=self.option.max_hops {
            if finished {
                break;
            }

            setsockopt(&socket_instance, sockopt::Ipv4Ttl, &ttl).map_err(|e| {
                Error::new(Status::GenericFailure, format!("Failed to set TTL: {}", e))
            })?;

            let mut res = HopResult {
                hop: ttl,
                addr: None,
                rtt: Vec::new(),
            };

            let re_try = self.option.re_try.unwrap_or(3);
            for _ in 0..re_try {
                let mut icmp_buffer = [0u8; BUFFER_SIZE];
                let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
                icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                icmp_packet.set_icmp_code(IcmpCode::new(0));

                icmp_packet.set_sequence_number(ttl as u16);
                icmp_packet.set_identifier(std::process::id() as u16);

                let checksum =
                    pnet::packet::icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
                icmp_packet.set_checksum(checksum);

                let start_time = Instant::now();

                sendto(
                    socket_instance.as_raw_fd(),
                    icmp_packet.packet(),
                    &dest,
                    MsgFlags::empty(),
                )
                .map_err(|e| {
                    Error::new(
                        Status::GenericFailure,
                        format!("Failed to send packet: {}", e),
                    )
                })?;

                let mut buffer = vec![0u8; 1024];
                let mut iov = [IoSliceMut::new(&mut buffer)];

                let mut cmsg_buffer = vec![0u8; 64];

                // Try recvmsg at first
                match recvmsg::<SockaddrIn>(
                    socket_instance.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg_buffer),
                    MsgFlags::MSG_ERRQUEUE,
                ) {
                    Ok(msg) => match msg.cmsgs() {
                        Ok(cmsgs) => {
                            for cmsg in cmsgs {
                                if let ControlMessageOwned::Ipv4RecvErr(err, addr) = cmsg {
                                    match IcmpType::new(err.ee_type) {
                                        IcmpTypes::TimeExceeded => {
                                            let end_time = Instant::now();
                                            let rtt =
                                                end_time.duration_since(start_time).as_secs_f64()
                                                    * 1000.0;
                                            res.rtt.push(rtt);
                                            if let Some(addr) = addr {
                                                res.addr = Some(
                                                    Ipv4Addr::from(u32::from_be(
                                                        addr.sin_addr.s_addr,
                                                    ))
                                                    .to_string(),
                                                );
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    },
                    Err(_) => {
                        // Then try recvfrom
                        match recvfrom::<SockaddrIn>(socket_instance.as_raw_fd(), &mut buffer) {
                            Ok((size, src_addr)) => {
                                if let Some(ipv4_packet) = Ipv4Packet::new(&buffer[..size]) {
                                    let icmp_payload = ipv4_packet.payload();

                                    if let Some(icmp) = IcmpPacket::new(icmp_payload) {
                                        match icmp.get_icmp_type() {
                                            IcmpTypes::EchoReply => {
                                                let end_time = Instant::now();
                                                let rtt = end_time
                                                    .duration_since(start_time)
                                                    .as_secs_f64()
                                                    * 1000.0;
                                                res.rtt.push(rtt);
                                                if let Some(addr) = src_addr {
                                                    res.addr = Some(addr.ip().to_string());
                                                }
                                                finished = true;
                                                break 'finish;
                                            }
                                            IcmpTypes::TimeExceeded => {
                                                let end_time = Instant::now();
                                                let rtt = end_time
                                                    .duration_since(start_time)
                                                    .as_secs_f64()
                                                    * 1000.0;
                                                res.rtt.push(rtt);
                                                if let Some(addr) = src_addr {
                                                    res.addr = Some(addr.ip().to_string());
                                                }
                                            }
                                            t => {
                                                return Err(Error::from_reason(format!(
                                                    "Unknown ICMP type: {:?}",
                                                    t
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                return Err(Error::from_reason("Failed to receive packet"));
                            }
                        }
                    }
                }
            }
            results.push(res.clone());
        }

        Ok(results)
    }

    fn trace_ipv6(&self, dest_ip: Ipv6Addr) -> Result<Vec<HopResult>> {
        let mut finished = false;
        let socket_instance = socket(
            AddressFamily::Inet6,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::IcmpV6,
        )
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create socket: {}", e),
            )
        })?;

        let timeout = TimeVal::new(self.option.timeout.into(), 0);
        setsockopt(&socket_instance, sockopt::ReceiveTimeout, &timeout).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to set read timeout: {}", e),
            )
        })?;

        // allow recvmsg when timeout
        setsockopt(&socket_instance, sockopt::Ipv6RecvErr, &true).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to set EQUEUE: {}", e),
            )
        })?;

        let dest = SockaddrIn6::from(SocketAddrV6::new(dest_ip, 0, 0, 0));

        let mut results = Vec::new();

        'finish: for ttl in 1..=self.option.max_hops {
            if finished {
                break;
            }

            setsockopt(&socket_instance, sockopt::Ipv6Ttl, &ttl).map_err(|e| {
                Error::new(Status::GenericFailure, format!("Failed to set TTL: {}", e))
            })?;

            let mut res = HopResult {
                hop: ttl,
                addr: None,
                rtt: Vec::new(),
            };

            let re_try = self.option.re_try.unwrap_or(3);
            for _ in 0..re_try {
                let mut icmp_buffer = [0u8; BUFFER_SIZE];
                let mut icmp_packet = Ipv6MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
                icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                icmp_packet.set_icmpv6_code(Icmpv6Code::new(0));

                icmp_packet.set_sequence_number(ttl as u16);
                icmp_packet.set_identifier(std::process::id() as u16);

                let sum = pnet::packet::icmpv6::checksum(
                    &Icmpv6Packet::new(icmp_packet.packet()).unwrap(),
                    &Ipv6Addr::LOCALHOST,
                    &dest_ip,
                );

                icmp_packet.set_checksum(sum);

                let start_time = Instant::now();

                sendto(
                    socket_instance.as_raw_fd(),
                    icmp_packet.packet(),
                    &dest,
                    MsgFlags::empty(),
                )
                .map_err(|e| {
                    Error::new(
                        Status::GenericFailure,
                        format!("Failed to send packet: {}", e),
                    )
                })?;

                let mut buffer = vec![0u8; 1024];
                let mut iov = [IoSliceMut::new(&mut buffer)];

                let mut cmsg_buffer = vec![0u8; 64];

                // Try recvmsg at first
                match recvmsg::<SockaddrIn>(
                    socket_instance.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg_buffer),
                    MsgFlags::MSG_ERRQUEUE,
                ) {
                    Ok(msg) => match msg.cmsgs() {
                        Ok(cmsgs) => {
                            for cmsg in cmsgs {
                                if let ControlMessageOwned::Ipv6RecvErr(err, addr) = cmsg {
                                    match IcmpType::new(err.ee_type) {
                                        IcmpTypes::TimeExceeded => {
                                            let end_time = Instant::now();
                                            let rtt =
                                                end_time.duration_since(start_time).as_secs_f64()
                                                    * 1000.0;
                                            res.rtt.push(rtt);
                                            if let Some(addr) = addr {
                                                res.addr = Some(
                                                    Ipv6Addr::from(addr.sin6_addr.s6_addr)
                                                        .to_string(),
                                                );
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    },
                    Err(_) => {
                        // Then try recvfrom
                        match recvfrom::<SockaddrIn>(socket_instance.as_raw_fd(), &mut buffer) {
                            Ok((size, src_addr)) => {
                                if let Some(ipv6_packet) = Ipv6Packet::new(&buffer[..size]) {
                                    let icmp_payload = ipv6_packet.payload();

                                    if let Some(icmp) = Icmpv6Packet::new(icmp_payload) {
                                        match icmp.get_icmpv6_type() {
                                            Icmpv6Types::EchoReply => {
                                                let end_time = Instant::now();
                                                let rtt = end_time
                                                    .duration_since(start_time)
                                                    .as_secs_f64()
                                                    * 1000.0;
                                                res.rtt.push(rtt);
                                                if let Some(addr) = src_addr {
                                                    res.addr = Some(addr.ip().to_string());
                                                }
                                                finished = true;
                                                break 'finish;
                                            }
                                            Icmpv6Types::TimeExceeded => {
                                                let end_time = Instant::now();
                                                let rtt = end_time
                                                    .duration_since(start_time)
                                                    .as_secs_f64()
                                                    * 1000.0;
                                                res.rtt.push(rtt);
                                                if let Some(addr) = src_addr {
                                                    res.addr = Some(addr.ip().to_string());
                                                }
                                            }
                                            t => {
                                                return Err(Error::from_reason(format!(
                                                    "Unknown ICMP type: {:?}",
                                                    t
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                return Err(Error::from_reason("Failed to receive packet"));
                            }
                        }
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
        max_hops: 64,
        timeout: 1,
        ip_version: None,
        re_try: Some(3),
    });

    AsyncTask::new(TraceTask { target, option })
}
