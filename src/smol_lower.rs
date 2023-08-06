use log::{debug, info};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{wait as phy_wait, ChecksumCapabilities, Device, Medium, TunTapInterface};
use smoltcp::socket::raw::{self, RecvError as SmolRecvError};
use smoltcp::time::Instant;
use smoltcp::wire::{
    self, IpCidr, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpPacket,
};
use std::os::fd::AsRawFd;
use thiserror::Error;

pub struct SmolLower<'a> {
    addr: Ipv4Address,
    listen_port: u16,
    interface: Interface,
    device: TunTapInterface,
    sockets: SocketSet<'a>,
    raw_sock_handle: SocketHandle,
}

#[derive(Error, Debug)]
pub enum RecvError {
    #[error("receive timed out")]
    Timeout,

    #[error("received malformed IP packet")]
    MalformedIp(wire::Error),

    #[error("received malformed TCP packet")]
    MalformedTcp(wire::Error),

    #[error("other receive error")]
    RecvError(SmolRecvError),
}

impl SmolLower<'_> {
    pub fn new(local_addr: Ipv4Address) -> anyhow::Result<Self> {
        let mut device = TunTapInterface::new("tun-st", Medium::Ip)?;
        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::now());

        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(local_addr.into(), 24))
                .expect("too many addresses");
        });

        let raw_rx_buffer =
            raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 64], vec![0; 1 << 17]);
        let raw_tx_buffer =
            raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 64], vec![0; 1 << 17]);
        let raw_sock = raw::Socket::new(
            IpVersion::Ipv4,
            IpProtocol::Tcp,
            raw_rx_buffer,
            raw_tx_buffer,
        );

        let mut sockets = SocketSet::new(vec![]);
        let raw_sock_handle = sockets.add(raw_sock);

        info!("listening on {}", iface.ipv4_addr().unwrap());

        Ok(Self {
            addr: local_addr,
            listen_port: 555,
            interface: iface,
            device,
            sockets,
            raw_sock_handle,
        })
    }

    pub fn checksum_caps(&self) -> ChecksumCapabilities {
        self.device.capabilities().checksum
    }

    pub fn send(&mut self, dst: Ipv4Address, payload: &[u8]) -> anyhow::Result<()> {
        let caps = self.checksum_caps();
        let socket = self.sockets.get_mut::<raw::Socket>(self.raw_sock_handle);

        let ipv4 = Ipv4Repr {
            src_addr: self.addr,
            dst_addr: dst,
            payload_len: payload.len(),
            hop_limit: 64,
            next_header: IpProtocol::Tcp,
        };

        let mut buf = socket.send(ipv4.buffer_len() + ipv4.payload_len)?;

        ipv4.emit(&mut Ipv4Packet::new_unchecked(&mut buf), &caps);

        buf[ipv4.buffer_len()..].copy_from_slice(payload);

        // poll interface to actually send
        self.interface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);

        Ok(())
    }

    pub fn recv(
        &mut self,
        deadline: Option<Instant>,
    ) -> Result<(Ipv4Address, TcpPacket<Vec<u8>>), RecvError> {
        loop {
            let timestamp = Instant::now();

            if let Some(time_limit) = deadline {
                if timestamp >= time_limit {
                    return Err(RecvError::Timeout);
                }
            }

            let socket = self.sockets.get_mut::<raw::Socket>(self.raw_sock_handle);

            if socket.can_recv() {
                let raw = socket.recv().map_err(RecvError::RecvError)?;
                let ipv4_packet = Ipv4Packet::new_checked(raw).map_err(RecvError::MalformedIp)?;

                if ipv4_packet.dst_addr() != self.addr {
                    debug!("Skipping packet for {}", ipv4_packet.dst_addr());
                    continue;
                }

                assert_eq!(ipv4_packet.next_header(), IpProtocol::Tcp);

                let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload().to_owned())
                    .map_err(RecvError::MalformedTcp)?;

                if tcp_packet.dst_port() != self.listen_port {
                    continue;
                }

                return Ok((ipv4_packet.src_addr(), tcp_packet));
            }

            phy_wait(self.device.as_raw_fd(), deadline.map(|t| t - timestamp)).unwrap();

            self.interface
                .poll(timestamp, &mut self.device, &mut self.sockets);
        }
    }
}
