use anyhow::Result;
use log::{info, warn};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber},
};
use std::{marker::PhantomData, net::Ipv4Addr, ops::AddAssign};

use crate::smol_channel::{Ack, FinAck, Syn, SynAck};

pub struct LocalAddr {
    pub addr: Ipv4Addr,
    pub checksum_caps: ChecksumCapabilities,
    pub port: u16,
}
pub struct RemoteAddr {
    addr: Ipv4Addr,
    port: u16,
}

pub trait ChannelFilter<T> {
    fn filter(&self, packet: &T) -> bool;
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
pub struct FinWait1;
pub struct FinWait2;
pub struct CloseWait;
pub struct LastAck;

impl TcpState for SynRcvd {}
impl TcpState for Established {}
impl TcpState for FinWait1 {}
impl TcpState for FinWait2 {}
impl TcpState for CloseWait {}
impl TcpState for LastAck {}

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
        let syn = TcpRepr::parse(
            &TcpPacket::new_unchecked(syn.packet.as_ref()),
            &IpAddress::from(remote),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        let iss = TcpSeqNumber(123); // TODO generate random
        let mut tcb = Tcb {
            irs: syn.seq_number,
            rcv_nxt: syn.seq_number + syn.segment_len(),
            rcv_wnd: syn.window_len,

            iss,
            snd_una: iss,
            snd_nxt: iss,
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
        tcb.snd_nxt.add_assign(resp.segment_len());

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

impl ChannelFilter<Vec<u8>> for TcpListen {
    fn filter(&self, packet: &Vec<u8>) -> bool {
        // This is a bit janky but it works for now
        if let Ok(tcp) = TcpPacket::new_checked(packet) {
            if tcp.syn() == true
                && tcp.ack() == false
                && tcp.rst() == false
                && tcp.fin() == false
                && tcp.psh() == false
            {
                return true;
            }
        }
        warn!("Dropping non-SYN");
        false
    }
}

impl<T> ChannelFilter<Vec<u8>> for Tcp<T>
where
    T: TcpState,
{
    fn filter(&self, packet: &Vec<u8>) -> bool {
        let packet = TcpPacket::new_checked(packet).unwrap();

        if packet.dst_port() == self.local.port && packet.src_port() == self.remote.port {
            true
        } else {
            warn!("dropping packet to wrong port");
            false
        }
    }
}

impl<T> Tcp<T>
where
    T: TcpState,
{
    fn build_ack_raw(&mut self, payload: &[u8], fin: bool) -> Vec<u8> {
        let control = if fin {
            TcpControl::Fin
        } else {
            TcpControl::None
        };
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            control,
            seq_number: self.tcb.snd_nxt,
            ack_number: Some(self.tcb.rcv_nxt),
            window_len: self.tcb.rcv_wnd,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload,
        };

        self.tcb.snd_nxt.add_assign(repr.segment_len());

        let mut buf = vec![0; repr.buffer_len()];
        let mut packet = TcpPacket::new_unchecked(&mut buf);

        repr.emit(
            &mut packet,
            &IpAddress::from(self.local.addr),
            &IpAddress::from(self.remote.addr),
            &self.local.checksum_caps,
        );

        buf
    }

    fn build_ack(&mut self, payload: &[u8]) -> Ack {
        Ack {
            packet: self.build_ack_raw(payload, false),
        }
    }

    fn build_fin(&mut self) -> FinAck {
        FinAck {
            packet: self.build_ack_raw(&[], true),
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

        // TODO we need to handle more cases here
        // and check ACK numbers

        if self.tcb.rcv_nxt == ack.seq_number {
            self.tcb.rcv_nxt.add_assign(ack.segment_len());

            let resp = self.build_ack(&[]);
            (resp, ack.payload)
        } else {
            todo!("out of order packets not implemented")
        }
    }

    pub fn recv_fin(mut self, fin: &FinAck) -> (Tcp<CloseWait>, Ack) {
        // TODO also handle data here
        let fin = TcpPacket::new_checked(&fin.packet).unwrap();
        let fin = TcpRepr::parse(
            &fin,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        if fin.seq_number == self.tcb.rcv_nxt {
            self.tcb.rcv_nxt.add_assign(fin.segment_len());
        } else {
            todo!("out of order packets not implemented")
        }

        let ack = self.build_ack(&[]);
        (
            Tcp {
                local: self.local,
                remote: self.remote,
                tcb: self.tcb,
                _marker: PhantomData,
            },
            ack,
        )
    }

    pub fn send(&mut self, data: &[u8]) -> Ack {
        self.build_ack(data)
    }

    pub fn close(mut self) -> (Tcp<FinWait1>, FinAck) {
        let fin = self.build_fin();
        (
            Tcp {
                local: self.local,
                remote: self.remote,
                tcb: self.tcb,
                _marker: PhantomData,
            },
            fin,
        )
    }
}

impl Tcp<FinWait1> {
    pub fn recv(self, ack: &Ack) -> Tcp<FinWait2> {
        let ack = TcpPacket::new_checked(&ack.packet).unwrap();
        let ack = TcpRepr::parse(
            &ack,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        if ack.segment_len() > 0 {
            panic!("got data in FIN_WAIT_1");
        }

        if ack.ack_number == Some(self.tcb.snd_nxt) {
            // ACK of our FIN, we can transition to FIN_WAIT_2
            Tcp {
                local: self.local,
                remote: self.remote,
                tcb: self.tcb,
                _marker: PhantomData,
            }
        } else {
            todo!("out of order packets not implemented")
        }
    }
}

impl Tcp<FinWait2> {
    pub fn recv_ack(&mut self, _ack: &Ack) -> Ack {
        let ack = TcpPacket::new_checked(&_ack.packet).unwrap();
        let ack = TcpRepr::parse(
            &ack,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        if Some(self.tcb.snd_nxt) != ack.ack_number {
            warn!("got out of order ACK");
        }

        if self.tcb.rcv_nxt == ack.seq_number {
            self.tcb.rcv_nxt.add_assign(ack.segment_len());
        } else {
            todo!("out of order packets not implemented")
        }

        self.build_ack(&[])
    }

    pub fn recv_fin(mut self, fin: &FinAck) -> Ack {
        let fin = TcpPacket::new_checked(&fin.packet).unwrap();
        let fin = TcpRepr::parse(
            &fin,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        if fin.seq_number == self.tcb.rcv_nxt {
            self.tcb.rcv_nxt.add_assign(1);
        } else {
            todo!("out of order packets not implemented")
        }

        // TODO check stuff

        self.build_ack(&[])
    }
}

impl Tcp<CloseWait> {
    pub fn recv_ack(&mut self, ack: &Ack) {
        let ack = TcpPacket::new_checked(&ack.packet).unwrap();
        let ack = TcpRepr::parse(
            &ack,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        if Some(self.tcb.snd_nxt) != ack.ack_number {
            warn!("got out of order ACK");
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Ack {
        self.build_ack(data)
    }

    pub fn close(mut self) -> (Tcp<LastAck>, FinAck) {
        let fin = self.build_fin();
        (
            Tcp {
                local: self.local,
                remote: self.remote,
                tcb: self.tcb,
                _marker: PhantomData,
            },
            fin,
        )
    }
}

impl Tcp<LastAck> {
    pub fn recv_ack(self, ack: &Ack) {
        let ack = TcpPacket::new_checked(&ack.packet).unwrap();
        let ack = TcpRepr::parse(
            &ack,
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();

        if Some(self.tcb.snd_nxt) != ack.ack_number {
            warn!("got out of order ACK");
        }
    }
}
