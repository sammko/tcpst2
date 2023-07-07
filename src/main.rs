use anyhow::Result;
use log::{debug, info, trace};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{wait as phy_wait, Device, Medium, TunTapInterface};
use smoltcp::socket::raw;
use smoltcp::time::Instant;
use smoltcp::wire::{
    IpAddress, IpCidr, IpProtocol, IpRepr, IpVersion, Ipv4Address, Ipv4Packet, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber,
};
use std::os::unix::io::AsRawFd;

fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut device = TunTapInterface::new("tun0", Medium::Ip)?;
    let fd = device.as_raw_fd();
    let device_caps = device.capabilities();
    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::now());

    let our_ipv4 = Ipv4Address::new(192, 168, 22, 1);

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::Ipv4(our_ipv4), 24))
            .expect("too many addresses");
    });

    let raw_rx_buffer = raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY], vec![0; 2048]);
    let raw_tx_buffer = raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY], vec![0; 2048]);
    let raw_sock = raw::Socket::new(
        IpVersion::Ipv4,
        IpProtocol::Tcp,
        raw_rx_buffer,
        raw_tx_buffer,
    );

    let mut sockets = SocketSet::new(vec![]);
    let raw_sock_handle = sockets.add(raw_sock);

    info!("listening on {}", iface.ipv4_addr().unwrap());

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<raw::Socket>(raw_sock_handle);

        while socket.can_recv() {
            let payload = socket.recv()?;
            let packet = Ipv4Packet::new_checked(&payload)?;
            let dst = packet.dst_addr();
            if dst != our_ipv4 {
                trace!("skipping packet for {}", dst);
                continue;
            }
            assert_eq!(packet.next_header(), IpProtocol::Tcp);

            let dst = dst.into_address();
            let src = packet.src_addr().into_address();

            let tcp_packet = TcpPacket::new_checked(packet.payload())?;
            let tcp_repr = TcpRepr::parse(&tcp_packet, &src, &dst, &device_caps.checksum)?;
            trace!("received packet: {:?}", tcp_repr);

            if tcp_repr.control == TcpControl::Syn
                && tcp_repr.ack_number.is_none()
                && tcp_repr.dst_port == 884
            {
                info!("accepting connection from {}", src);
                let r_tcp_repr = TcpRepr {
                    src_port: tcp_repr.dst_port,
                    dst_port: tcp_repr.src_port,
                    control: TcpControl::Syn,
                    seq_number: TcpSeqNumber(0),
                    ack_number: Some(tcp_repr.seq_number + 1),
                    window_len: 1024,
                    window_scale: None,
                    max_seg_size: None,
                    sack_permitted: false,
                    sack_ranges: [None, None, None],
                    payload: &[],
                };
                trace!("sending packet: {:?}", r_tcp_repr);
                let IpRepr::Ipv4(r_ipv4_repr) =
                    IpRepr::new(dst, src, IpProtocol::Tcp, r_tcp_repr.buffer_len(), 64);

                debug!("tcp repr buffer len: {}", r_tcp_repr.buffer_len());

                let r_buf = socket.send(r_ipv4_repr.buffer_len() + r_ipv4_repr.payload_len)?;
                let mut r_ip_packet = Ipv4Packet::new_unchecked(r_buf);
                r_ipv4_repr.emit(&mut r_ip_packet, &device_caps.checksum);

                debug!(
                    "r_ip_packet payload len: {}",
                    r_ip_packet.payload_mut().len()
                );

                r_tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(r_ip_packet.payload_mut()),
                    &dst,
                    &src,
                    &device_caps.checksum,
                );
            }
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets))?;
    }
}
