#![allow(unused_assignments)]

use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::*,
    threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode},
    Error, Result, ScopedTask, Status,
};
use nix::sys::{
    socket::{
        recvfrom, recvmsg, sendto, setsockopt, socket, sockopt, AddressFamily, ControlMessageOwned,
        MsgFlags, SockFlag, SockProtocol, SockType, SockaddrIn, SockaddrIn6, SockaddrLike,
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
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::{io::IoSliceMut, net::SocketAddrV6};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddrV4},
    os::fd::{OwnedFd, RawFd},
};
use std::{
    net::{Ipv4Addr, ToSocketAddrs},
    time::Instant,
};
use std::{thread, time::Duration};

const ICMP_HEADER_SIZE: usize = 8;
const ICMP_PAYLOAD_SIZE: usize = 32;
const BUFFER_SIZE: usize = ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE;
const POLL_INTERVAL_MS: u64 = 1; // 轮询间隔时间（毫秒）
const MAX_POLL_ITERATIONS: u32 = 1000; // 最大轮询次数

#[napi(object)]
pub struct TraceOption<'env> {
    /// Max hops
    /// @default 64
    pub max_hops: Option<i32>,
    /// Timeout
    /// @default 1
    /// @unit second
    pub timeout: Option<i32>,
    #[napi(ts_type = "'v4' | 'v6' | 'auto'")]
    pub ip_version: Option<String>,
    /// Retry times every hops
    /// @default 3
    pub re_try: Option<i32>,

    /// Callback function when trace result
    #[napi(ts_type = "((err: Error | null, hop: HopResult) => void) | undefined")]
    pub on_trace: Option<Function<'env, HopResult, ()>>,
}

pub struct BaseTraceOption {
    pub max_hops: i32,
    pub timeout: i32,
    pub ip_version: String,
    pub re_try: i32,
}

pub struct TraceTask {
    target: String,
    option: BaseTraceOption,
    on_trace: Option<ThreadsafeFunction<HopResult, (), HopResult>>,
}

#[derive(Debug, Clone)]
#[napi(object)]
pub struct HopResult {
    /// hop index
    pub hop: i32,
    /// current hop's target ip address
    pub addr: Option<String>,
    /// rtt
    pub rtt: Vec<f64>,
}

impl<'a> ScopedTask<'a> for TraceTask {
    type Output = Vec<HopResult>;
    type JsValue = Vec<HopResult>;

    fn compute(&mut self) -> Result<Self::Output> {
        let preferred_ip_version = self.option.ip_version.clone();
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

                match preferred_ip_version.as_str() {
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

    fn resolve(&mut self, _: &'a Env, output: Vec<HopResult>) -> Result<Self::JsValue> {
        Ok(output)
    }

    fn reject(&mut self, _: &'a Env, err: Error) -> Result<Self::JsValue> {
        Err(err)
    }
}

impl TraceTask {
    /// 创建非阻塞IPv4 socket
    fn create_nonblocking_ipv4_socket(&self) -> Result<OwnedFd> {
        let socket_instance = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK, // 设置为非阻塞模式
            SockProtocol::Icmp,
        )
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create IPv4 socket: {}", e),
            )
        })?;

        // 设置socket选项
        self.configure_socket(&socket_instance, true)?;
        Ok(socket_instance)
    }

    /// 创建非阻塞IPv6 socket
    fn create_nonblocking_ipv6_socket(&self) -> Result<OwnedFd> {
        let socket_instance = socket(
            AddressFamily::Inet6,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK, // 设置为非阻塞模式
            SockProtocol::IcmpV6,
        )
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create IPv6 socket: {}", e),
            )
        })?;

        // 设置socket选项
        self.configure_socket(&socket_instance, false)?;
        Ok(socket_instance)
    }

    /// 配置socket选项
    fn configure_socket(&self, socket_fd: &OwnedFd, is_ipv4: bool) -> Result<()> {
        let timeout = TimeVal::new(self.option.timeout.into(), 0);

        // 设置接收超时
        setsockopt(socket_fd, sockopt::ReceiveTimeout, &timeout).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to set read timeout: {}", e),
            )
        })?;

        // 设置错误队列接收
        if is_ipv4 {
            setsockopt(socket_fd, sockopt::Ipv4RecvErr, &true).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to set IPv4 EQUEUE: {}", e),
                )
            })?;
        } else {
            setsockopt(socket_fd, sockopt::Ipv6RecvErr, &true).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to set IPv6 EQUEUE: {}", e),
                )
            })?;
        }

        Ok(())
    }

    /// 非阻塞发送数据包
    fn send_packet_nonblocking<T: SockaddrLike>(
        &self,
        socket_fd: &OwnedFd,
        packet: &[u8],
        dest: &T,
    ) -> Result<()> {
        let mut retry_count = 0;
        const MAX_SEND_RETRIES: u32 = 10;

        loop {
            match sendto(socket_fd.as_raw_fd(), packet, dest, MsgFlags::empty()) {
                Ok(_) => return Ok(()),
                Err(nix::errno::Errno::EAGAIN) => {
                    retry_count += 1;
                    if retry_count >= MAX_SEND_RETRIES {
                        return Err(Error::new(
                            Status::GenericFailure,
                            "Failed to send packet: socket buffer full".to_string(),
                        ));
                    }
                    // 短暂等待后重试
                    thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
                }
                Err(e) => {
                    return Err(Error::new(
                        Status::GenericFailure,
                        format!("Failed to send packet: {}", e),
                    ));
                }
            }
        }
    }

    /// 非阻塞接收响应（通用版本）
    fn receive_response_nonblocking(
        &self,
        socket_fd: &OwnedFd,
        start_time: Instant,
        is_ipv4: bool,
    ) -> Result<Option<(String, f64)>> {
        let timeout_duration = Duration::from_secs(self.option.timeout as u64);
        let poll_start = Instant::now();
        let mut poll_count = 0;

        while poll_start.elapsed() < timeout_duration && poll_count < MAX_POLL_ITERATIONS {
            poll_count += 1;

            // 尝试从错误队列接收
            if let Some(result) =
                self.try_receive_from_error_queue(socket_fd.as_raw_fd(), start_time, is_ipv4)?
            {
                return Ok(Some(result));
            }

            // 尝试常规接收
            if let Some(result) =
                self.try_receive_regular(socket_fd.as_raw_fd(), start_time, is_ipv4)?
            {
                return Ok(Some(result));
            }

            // 短暂休眠避免过度占用CPU
            thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        }

        Ok(None) // 超时或达到最大轮询次数
    }

    /// 尝试从错误队列接收消息
    fn try_receive_from_error_queue(
        &self,
        socket_fd: RawFd,
        start_time: Instant,
        is_ipv4: bool,
    ) -> Result<Option<(String, f64)>> {
        let mut buffer = vec![0u8; 1024];
        let mut iov = [IoSliceMut::new(&mut buffer)];
        let mut cmsg_buffer = vec![0u8; 128]; // 增大控制消息缓冲区

        match recvmsg::<SockaddrIn>(
            socket_fd,
            &mut iov,
            Some(&mut cmsg_buffer),
            MsgFlags::MSG_ERRQUEUE,
        ) {
            Ok(msg) => {
                if let Ok(cmsgs) = msg.cmsgs() {
                    for cmsg in cmsgs {
                        if is_ipv4 {
                            if let ControlMessageOwned::Ipv4RecvErr(err, addr) = cmsg {
                                if let Some(result) =
                                    self.handle_ipv4_error_message(err, addr, start_time)
                                {
                                    return Ok(Some(result));
                                }
                            }
                        } else {
                            if let ControlMessageOwned::Ipv6RecvErr(err, addr) = cmsg {
                                if let Some(result) =
                                    self.handle_ipv6_error_message(err, addr, start_time)
                                {
                                    return Ok(Some(result));
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("recvmsg error: {:?}", e);
                // 其他错误，忽略
            }
        }

        Ok(None)
    }

    /// 尝试常规接收
    fn try_receive_regular(
        &self,
        socket_fd: i32,
        start_time: Instant,
        is_ipv4: bool,
    ) -> Result<Option<(String, f64)>> {
        let mut buffer = vec![0u8; 1024];

        match recvfrom::<SockaddrIn>(socket_fd, &mut buffer) {
            Ok((size, src_addr)) => {
                if is_ipv4 {
                    if let Some(result) =
                        self.handle_ipv4_packet(&buffer[..size], src_addr, start_time)?
                    {
                        return Ok(Some(result));
                    }
                } else {
                    if let Some(result) =
                        self.handle_ipv6_packet(&buffer[..size], src_addr, start_time)?
                    {
                        return Ok(Some(result));
                    }
                }
            }
            Err(e) => {
                eprintln!("recvfrom error: {:?}", e);
                // 其他错误，忽略
            }
        }

        Ok(None)
    }

    /// 处理IPv4错误消息
    fn handle_ipv4_error_message(
        &self,
        err: nix::libc::sock_extended_err,
        addr: Option<nix::libc::sockaddr_in>,
        start_time: Instant,
    ) -> Option<(String, f64)> {
        match IcmpType::new(err.ee_type) {
            IcmpTypes::TimeExceeded => {
                let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                let addr_str =
                    addr.map(|a| Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).to_string());
                Some((addr_str.unwrap_or_default(), rtt))
            }
            _ => None,
        }
    }

    /// 处理IPv6错误消息
    fn handle_ipv6_error_message(
        &self,
        err: nix::libc::sock_extended_err,
        addr: Option<nix::libc::sockaddr_in6>,
        start_time: Instant,
    ) -> Option<(String, f64)> {
        match IcmpType::new(err.ee_type) {
            IcmpTypes::TimeExceeded => {
                let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                let addr_str = addr.map(|a| Ipv6Addr::from(a.sin6_addr.s6_addr).to_string());
                Some((addr_str.unwrap_or_default(), rtt))
            }
            _ => None,
        }
    }

    /// 处理IPv4数据包
    fn handle_ipv4_packet(
        &self,
        buffer: &[u8],
        src_addr: Option<SockaddrIn>,
        start_time: Instant,
    ) -> Result<Option<(String, f64)>> {
        if let Some(ipv4_packet) = Ipv4Packet::new(buffer) {
            let icmp_payload = ipv4_packet.payload();

            if let Some(icmp) = IcmpPacket::new(icmp_payload) {
                match icmp.get_icmp_type() {
                    IcmpTypes::EchoReply => {
                        let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                        let addr_str = src_addr.map(|a| a.ip().to_string()).unwrap_or_default();
                        return Ok(Some((addr_str, rtt)));
                    }
                    IcmpTypes::TimeExceeded => {
                        let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                        let addr_str = src_addr.map(|a| a.ip().to_string()).unwrap_or_default();
                        return Ok(Some((addr_str, rtt)));
                    }
                    t => {
                        return Err(Error::from_reason(format!("Unknown ICMP type: {:?}", t)));
                    }
                }
            }
        }
        Ok(None)
    }

    /// 处理IPv6数据包
    fn handle_ipv6_packet(
        &self,
        buffer: &[u8],
        src_addr: Option<SockaddrIn>,
        start_time: Instant,
    ) -> Result<Option<(String, f64)>> {
        if let Some(ipv6_packet) = Ipv6Packet::new(buffer) {
            let icmp_payload = ipv6_packet.payload();

            if let Some(icmp) = Icmpv6Packet::new(icmp_payload) {
                match icmp.get_icmpv6_type() {
                    Icmpv6Types::EchoReply => {
                        let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                        let addr_str = src_addr.map(|a| a.ip().to_string()).unwrap_or_default();
                        return Ok(Some((addr_str, rtt)));
                    }
                    Icmpv6Types::TimeExceeded => {
                        let rtt = start_time.elapsed().as_secs_f64() * 1000.0;
                        let addr_str = src_addr.map(|a| a.ip().to_string()).unwrap_or_default();
                        return Ok(Some((addr_str, rtt)));
                    }
                    t => {
                        return Err(Error::from_reason(format!("Unknown ICMPv6 type: {:?}", t)));
                    }
                }
            }
        }
        Ok(None)
    }

    fn trace_ipv4(&self, dest_ip: Ipv4Addr) -> Result<Vec<HopResult>> {
        let mut finished = false;
        let socket_fd = self.create_nonblocking_ipv4_socket()?;
        let dest = SockaddrIn::from(SocketAddrV4::new(dest_ip, 0));
        let mut results = Vec::new();

        'finish: for ttl in 1..=self.option.max_hops {
            if finished {
                break;
            }

            // 设置TTL
            setsockopt(&socket_fd, sockopt::Ipv4Ttl, &ttl).map_err(|e| {
                Error::new(Status::GenericFailure, format!("Failed to set TTL: {}", e))
            })?;

            let mut res = HopResult {
                hop: ttl,
                addr: None,
                rtt: Vec::new(),
            };

            let re_try = self.option.re_try;
            for probe in 0..re_try {
                // 创建ICMP数据包
                let mut icmp_buffer = [0u8; BUFFER_SIZE];
                let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
                icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                icmp_packet.set_icmp_code(IcmpCode::new(0));
                icmp_packet.set_sequence_number((ttl * 1000 + probe) as u16); // 唯一序列号
                icmp_packet.set_identifier(std::process::id() as u16);

                // 计算校验和
                let checksum =
                    pnet::packet::icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
                icmp_packet.set_checksum(checksum);

                let start_time = Instant::now();

                // 非阻塞发送数据包
                self.send_packet_nonblocking(&socket_fd, icmp_packet.packet(), &dest)?;

                // 非阻塞接收响应
                match self.receive_response_nonblocking(&socket_fd, start_time, true)? {
                    Some((addr, rtt)) => {
                        res.rtt.push(rtt);
                        if res.addr.is_none() && !addr.is_empty() {
                            res.addr = Some(addr.clone());
                        }

                        // 检查是否到达目标
                        if addr == dest_ip.to_string() {
                            finished = true;
                        }
                    }
                    None => {
                        // 超时，继续下一次尝试
                    }
                }
            }

            if let Some(on_trace) = &self.on_trace {
                on_trace.call(Ok(res.clone()), ThreadsafeFunctionCallMode::NonBlocking);
            }

            results.push(res);
            if finished {
                break 'finish;
            }
        }

        Ok(results)
    }

    fn trace_ipv6(&self, dest_ip: Ipv6Addr) -> Result<Vec<HopResult>> {
        let mut finished = false;
        let socket_fd = self.create_nonblocking_ipv6_socket()?;
        let dest = SockaddrIn6::from(SocketAddrV6::new(dest_ip, 0, 0, 0));
        let mut results = Vec::new();

        'finish: for ttl in 1..=self.option.max_hops {
            if finished {
                break;
            }

            // 设置Hop Limit (IPv6的TTL)
            setsockopt(&socket_fd, sockopt::Ipv6Ttl, &ttl).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to set Hop Limit: {}", e),
                )
            })?;

            let mut res = HopResult {
                hop: ttl,
                addr: None,
                rtt: Vec::new(),
            };

            let re_try = self.option.re_try;
            for probe in 0..re_try {
                // 创建ICMPv6数据包
                let mut icmp_buffer = [0u8; BUFFER_SIZE];
                let mut icmp_packet = Ipv6MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
                icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                icmp_packet.set_icmpv6_code(Icmpv6Code::new(0));
                icmp_packet.set_sequence_number((ttl * 1000 + probe) as u16); // 唯一序列号
                icmp_packet.set_identifier(std::process::id() as u16);

                // 计算校验和
                let checksum = pnet::packet::icmpv6::checksum(
                    &Icmpv6Packet::new(icmp_packet.packet()).unwrap(),
                    &Ipv6Addr::LOCALHOST, // 源地址，实际应该使用本机地址
                    &dest_ip,
                );
                icmp_packet.set_checksum(checksum);

                let start_time = Instant::now();

                // 非阻塞发送数据包
                self.send_packet_nonblocking(&socket_fd, icmp_packet.packet(), &dest)?;

                // 非阻塞接收响应
                match self.receive_response_nonblocking(&socket_fd, start_time, false)? {
                    Some((addr, rtt)) => {
                        res.rtt.push(rtt);
                        if res.addr.is_none() && !addr.is_empty() {
                            res.addr = Some(addr.clone());
                        }

                        // 检查是否到达目标
                        if addr == dest_ip.to_string() {
                            finished = true;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(on_trace) = &self.on_trace {
                on_trace.call(Ok(res.clone()), ThreadsafeFunctionCallMode::NonBlocking);
            }

            results.push(res);
            if finished {
                break 'finish;
            }
        }

        Ok(results)
    }
}

#[allow(unused)]
#[napi(ts_return_type = "Promise<HopResult[]>")]
pub fn trace_route<'env>(
    target: String,
    options: Option<TraceOption>,
    signal: Option<AbortSignal>,
) -> Result<AsyncTask<TraceTask>> {
    let option = BaseTraceOption {
        max_hops: options.as_ref().and_then(|o| o.max_hops).unwrap_or(64),
        timeout: options.as_ref().and_then(|o| o.timeout).unwrap_or(1),
        ip_version: options
            .as_ref()
            .and_then(|o| o.ip_version.clone())
            .unwrap_or(String::from("auto")),
        re_try: options.as_ref().and_then(|o| o.re_try).unwrap_or(3),
    };

    let on_trace = options
        .and_then(|o| o.on_trace)
        .and_then(|cb| {
            Some(
                cb.build_threadsafe_function()
                    .callee_handled::<true>()
                    .build(),
            )
        })
        .transpose()?;

    match signal {
        Some(signal) => Ok(AsyncTask::with_signal(
            TraceTask {
                target,
                option,
                on_trace,
            },
            signal,
        )),
        None => Ok(AsyncTask::new(TraceTask {
            target,
            option,
            on_trace,
        })),
    }
}
