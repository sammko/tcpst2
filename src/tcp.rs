use log::{info, warn};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber},
};
use std::{any::TypeId, marker::PhantomData, net::Ipv4Addr, ops::AddAssign};

use crate::smol_channel::{Ack, FinAck, Rst, SmolMessage, Syn, SynAck};

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

// type markers
pub struct SynRcvd;
pub struct Established;
pub struct FinWait1;
pub struct FinWait2;
pub struct CloseWait;
pub struct LastAck;

mod tcp_state {
    use super::*;

    impl TcpState for SynRcvd {}
    impl TcpState for Established {}
    impl TcpState for FinWait1 {}
    impl TcpState for FinWait2 {}
    impl TcpState for CloseWait {}
    impl TcpState for LastAck {}

    pub trait TcpState {}
}
use tcp_state::TcpState;

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
    // TODO look at unifying this with Tcp<T>.

    pub fn recv_syn(self, remote: Ipv4Addr, syn: &Syn) -> (Tcp<SynRcvd>, SynAck) {
        let syn = TcpRepr::parse(
            &TcpPacket::new_unchecked(syn.packet().as_ref()),
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
        resp.emit(
            &mut TcpPacket::new_unchecked(&mut resp_data),
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
            SynAck {
                packet: TcpPacket::new_unchecked(resp_data),
            },
        )
    }
}

impl<T> ChannelFilter<TcpPacket<T>> for TcpListen
where
    T: AsRef<[u8]>,
{
    fn filter(&self, packet: &TcpPacket<T>) -> bool {
        // This is a bit janky but it works for now
        if packet.syn() == true
            && packet.ack() == false
            && packet.rst() == false
            && packet.fin() == false
            && packet.psh() == false
        {
            true
        } else {
            warn!("Dropping non-SYN");
            false
        }
    }
}

impl<T, U> ChannelFilter<TcpPacket<U>> for Tcp<T>
where
    T: TcpState,
    U: AsRef<[u8]>,
{
    fn filter(&self, packet: &TcpPacket<U>) -> bool {
        if packet.dst_port() == self.local.port && packet.src_port() == self.remote.port {
            true
        } else {
            warn!("dropping packet to wrong port");
            false
        }
    }
}

#[must_use]
pub enum Reaction<'a> {
    Acceptable(Option<Ack>, Option<&'a [u8]>),
    NotAcceptable(Option<Ack>),
    Reset(Option<Rst>),
}

impl<T> Tcp<T>
where
    T: TcpState + 'static,
{
    fn build_ack_raw(&mut self, payload: &[u8], fin: bool) -> TcpPacket<Vec<u8>> {
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

        TcpPacket::new_unchecked(buf)
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

    /// Determine if a segment's sequence number and length are acceptable
    /// under the current receive window.
    ///
    /// Link: <https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4>
    fn is_seg_acceptable(&self, seg: &TcpRepr) -> bool {
        let seg_seq = seg.seq_number;
        let seg_len = seg.segment_len();
        let rcv_nxt = self.tcb.rcv_nxt;
        let rcv_wnd = usize::from(self.tcb.rcv_wnd);

        if seg.segment_len() == 0 {
            if rcv_wnd == 0 {
                seg_seq == rcv_nxt
            } else {
                rcv_nxt <= seg_seq && seg_seq < rcv_nxt + rcv_wnd
            }
        } else {
            if self.tcb.rcv_wnd == 0 {
                false
            } else {
                (rcv_nxt <= seg_seq && seg_seq < rcv_nxt + rcv_wnd)
                    || (rcv_nxt <= seg_seq + seg_len - 1
                        && seg_seq + seg_len - 1 < rcv_nxt + rcv_wnd)
            }
        }
    }

    fn accept<'a>(&mut self, seg: &TcpRepr<'a>) -> Reaction<'a> {
        if !self.is_seg_acceptable(seg) {
            let reply = if seg.control == TcpControl::Rst {
                None
            } else {
                Some(self.build_ack(&[]))
            };
            return Reaction::NotAcceptable(reply);
        }

        if seg.control == TcpControl::Rst {
            if seg.seq_number == self.tcb.rcv_nxt {
                // clean reset
                return Reaction::Reset(None);
            }
            // challenge ACK
            return Reaction::NotAcceptable(Some(self.build_ack(&[])));
        }

        // ignore Security

        if seg.control == TcpControl::Syn {
            // TODO not sure if this is right
            return Reaction::NotAcceptable(Some(self.build_ack(&[])));
        }

        match seg.ack_number {
            Some(ack_number) => {
                // TODO RFC 5961

                // SYN-RECEIVED STATE
                if TypeId::of::<T>() == TypeId::of::<SynRcvd>() {
                    if self.tcb.snd_una < ack_number && ack_number <= self.tcb.snd_nxt {
                        // TODO RFC 5961
                        self.tcb.snd_wnd = seg.window_len;
                        // self.tcb.snd_wl1 = seg.seq_number;
                        // self.tcb.snd_wl2 = ack_number;
                        return Reaction::Acceptable(None, None);
                    } else {
                        return Reaction::NotAcceptable(None);
                    }
                }

                if self.tcb.snd_una < ack_number && ack_number <= self.tcb.snd_nxt {
                    self.tcb.snd_una = ack_number;
                } else if ack_number > self.tcb.snd_nxt {
                    return Reaction::NotAcceptable(Some(self.build_ack(&[])));
                }

                // SND.UNA =< SEG.ACK =< SND.NXT
                if self.tcb.snd_una <= ack_number && ack_number <= self.tcb.snd_nxt {
                    warn!("TODO should update send window")
                }

                // ignore URG

                self.tcb.rcv_nxt += seg.segment_len();
                Reaction::Acceptable(
                    if seg.segment_len() > 0 {
                        Some(self.build_ack(&[]))
                    } else {
                        None
                    },
                    if seg.payload.len() > 0 {
                        Some(seg.payload)
                    } else {
                        None
                    },
                )
            }
            None => Reaction::NotAcceptable(None),
        }
    }

    fn parse<'a, M>(&self, packet: &'a M) -> TcpRepr<'a>
    where
        M: SmolMessage,
    {
        TcpRepr::parse(
            &TcpPacket::new_unchecked(packet.packet().as_ref()),
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap()
    }
}

impl Tcp<SynRcvd> {
    pub fn recv_ack(mut self, ack: &Ack) -> Tcp<Established> {
        let ack = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(None, None) => {
                info!("SynRcvd: got ack: {:?}", ack);
                Tcp {
                    local: self.local,
                    remote: self.remote,
                    tcb: self.tcb,
                    _marker: PhantomData,
                }
            }
            Reaction::Acceptable(_, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }
}

impl Tcp<Established> {
    pub fn recv<'a>(&mut self, ack: &'a Ack) -> (Option<Ack>, &'a [u8]) {
        let ack: TcpRepr<'a> = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(resp, Some(data)) => (resp, data),
            Reaction::Acceptable(resp, None) => (resp, &[]),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }

    pub fn recv_fin(mut self, fin: &FinAck) -> (Tcp<CloseWait>, Ack) {
        let fin = self.parse(fin);
        match self.accept(&fin) {
            Reaction::Acceptable(Some(ack), None) => (
                Tcp {
                    local: self.local,
                    remote: self.remote,
                    tcb: self.tcb,
                    _marker: PhantomData,
                },
                ack,
            ),
            Reaction::Acceptable(_, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
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
    pub fn recv(mut self, ack: &Ack) -> Tcp<FinWait2> {
        let ack = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(None, None) => Tcp {
                local: self.local,
                remote: self.remote,
                tcb: self.tcb,
                _marker: PhantomData,
            },
            Reaction::Acceptable(_, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }
}

impl Tcp<FinWait2> {
    pub fn recv_ack(&mut self, ack: &Ack) -> Ack {
        let ack = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(Some(ack), _) => ack,
            Reaction::Acceptable(None, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }

    pub fn recv_fin(mut self, fin: &FinAck) -> Ack {
        let fin = self.parse(fin);
        match self.accept(&fin) {
            Reaction::Acceptable(Some(ack), _) => ack,
            Reaction::Acceptable(None, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }
}

impl Tcp<CloseWait> {
    pub fn recv_ack(&mut self, ack: &Ack) {
        let ack = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(None, None) => {}
            Reaction::Acceptable(_, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
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
    pub fn recv_ack(mut self, ack: &Ack) {
        let ack = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(None, None) => {}
            Reaction::Acceptable(_, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }
}
