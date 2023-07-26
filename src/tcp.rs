use std::{marker::PhantomData, net::Ipv4Addr, ops::AddAssign};

use log::{info, warn};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber},
};

use crate::smol_channel::{Ack, Syn, SynAck};

pub struct LocalAddr {
    pub addr: Ipv4Addr,
    pub checksum_caps: ChecksumCapabilities,
    pub port: u16,
}
pub struct RemoteAddr {
    addr: Ipv4Addr,
    port: u16,
}

#[allow(dead_code)]
struct Tcb {
    iss: TcpSeqNumber,
    snd_una: TcpSeqNumber,
    snd_nxt: TcpSeqNumber,
    snd_wnd: u16,

    irs: TcpSeqNumber,
    rcv_nxt: TcpSeqNumber,
    rcv_wnd: u16,
}

pub struct TcpClosed;
pub struct TcpListen {
    local: LocalAddr,
}

// type markers
pub struct SynRcvd;
pub struct Established;

impl TcpState for SynRcvd {}
impl TcpState for Established {}

pub trait TcpState {} // TODO maybe seal this

pub struct Tcp<State>
where
    State: TcpState,
{
    local: LocalAddr,
    remote: RemoteAddr,
    tcb: Tcb,
    _marker: PhantomData<State>,
}

impl TcpClosed {
    pub fn new() -> Self {
        TcpClosed {}
    }

    pub fn open(self, local: LocalAddr) -> TcpListen {
        TcpListen { local }
    }
}

impl TcpListen {
    pub fn recv_syn(self, remote: Ipv4Addr, syn: &Syn) -> (Tcp<SynRcvd>, SynAck) {
        let syn = TcpPacket::new_checked(&syn.packet).unwrap();
        let syn = TcpRepr::parse(
            &syn,
            &IpAddress::from(remote),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        let iss = TcpSeqNumber(123); // TODO generate random
        let tcb = Tcb {
            irs: syn.seq_number,
            rcv_nxt: syn.seq_number + 1,
            rcv_wnd: syn.window_len,

            iss,
            snd_una: iss,
            snd_nxt: iss + 1,
            snd_wnd: 0,
        };

        let resp = TcpRepr {
            src_port: self.local.port,
            dst_port: syn.src_port,
            control: TcpControl::Syn,
            seq_number: iss,
            ack_number: Some(tcb.rcv_nxt),
            window_len: tcb.rcv_wnd,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        };
        let mut resp_data = vec![0; resp.buffer_len()];
        let mut resp_packet = TcpPacket::new_unchecked(&mut resp_data);
        resp.emit(
            &mut resp_packet,
            &IpAddress::from(self.local.addr),
            &IpAddress::from(remote),
            &self.local.checksum_caps,
        );

        (
            Tcp {
                local: self.local,
                remote: RemoteAddr {
                    addr: remote,
                    port: syn.src_port,
                },
                tcb,
                _marker: PhantomData,
            },
            SynAck { packet: resp_data },
        )
    }
}

impl<T> Tcp<T>
where
    T: TcpState,
{
    pub fn filter(&self, packet: &[u8]) -> bool {
        let packet = TcpPacket::new_checked(packet).unwrap();

        if packet.dst_port() == self.local.port && packet.src_port() == self.remote.port {
            true
        } else {
            warn!("dropping packet to wrong port");
            false
        }
    }
}

impl Tcp<SynRcvd> {
    pub fn recv_ack(self, ack: &Ack) -> Tcp<Established> {
        let ack = TcpPacket::new_checked(&ack.packet).unwrap();
        let ack = TcpRepr::parse(
            &ack,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        info!("got ack: {:?}", ack);

        Tcp {
            local: self.local,
            remote: self.remote,
            tcb: self.tcb,
            _marker: PhantomData,
        }
    }
}

impl Tcp<Established> {
    pub fn recv<'a>(&mut self, ack: &'a Ack) -> (Ack, &'a [u8]) {
        let ack = TcpPacket::new_checked(&ack.packet).unwrap();
        let ack = TcpRepr::parse(
            &ack,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        if self.tcb.rcv_nxt == ack.seq_number {
            self.tcb.rcv_nxt.add_assign(ack.payload.len());

            let resp = TcpRepr {
                src_port: self.local.port,
                dst_port: self.remote.port,
                control: TcpControl::None,
                seq_number: self.tcb.snd_nxt,
                ack_number: Some(self.tcb.rcv_nxt),
                window_len: self.tcb.rcv_wnd,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                payload: &[],
            };
            let mut resp_data = vec![0; resp.buffer_len()];
            let mut resp_packet = TcpPacket::new_unchecked(&mut resp_data);

            resp.emit(
                &mut resp_packet,
                &IpAddress::from(self.local.addr),
                &IpAddress::from(self.remote.addr),
                &self.local.checksum_caps,
            );

            (Ack { packet: resp_data }, ack.payload)
        } else {
            todo!("out of order packets not implemented")
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Ack {
        let tx = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            control: TcpControl::None,
            seq_number: self.tcb.snd_nxt,
            ack_number: Some(self.tcb.rcv_nxt),
            window_len: self.tcb.rcv_wnd,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: data,
        };
        self.tcb.snd_nxt.add_assign(data.len());
        let mut tx_buf = vec![0; tx.buffer_len()];
        let mut tx_packet = TcpPacket::new_unchecked(&mut tx_buf);

        tx.emit(
            &mut tx_packet,
            &IpAddress::from(self.local.addr),
            &IpAddress::from(self.remote.addr),
            &self.local.checksum_caps,
        );

        Ack { packet: tx_buf }
    }
}
