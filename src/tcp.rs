use log::{info, warn};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, Ipv4Address, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber},
};
use std::{any::TypeId, collections::VecDeque, marker::PhantomData};

use crate::smol_channel::{Ack, FinAck, Rst, SmolMessage, Syn, SynAck};

#[derive(Clone, Debug)]
pub struct LocalAddr {
    pub addr: Ipv4Address,
    pub checksum_caps: ChecksumCapabilities,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct RemoteAddr {
    addr: Ipv4Address,
    port: u16,
}

pub trait ChannelFilter<T> {
    fn filter(&self, from_addr: Ipv4Address, packet: &T) -> bool;
}

mod tcp_state {
    macro_rules! impl_tcp_state {
        ($($t:ident),*) => {
            $(
                #[derive(Clone, Copy, Debug)]
                pub struct $t;
                impl TcpState for $t {}
            )*
        }
    }

    impl_tcp_state!(
        SynRcvd,
        Established,
        FinWait1,
        FinWait2,
        CloseWait,
        LastAck,
        _ForPicker
    );

    pub trait TcpState {}
}
use tcp_state::*;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
struct Tcb {
    iss: TcpSeqNumber,
    snd_una: TcpSeqNumber,
    snd_nxt: TcpSeqNumber,

    snd_wnd: u16,
    snd_wl1: TcpSeqNumber,
    snd_wl2: TcpSeqNumber,

    irs: TcpSeqNumber,
    rcv_nxt: TcpSeqNumber,
    rcv_wnd: u16,
}

pub struct TcpClosed;
pub struct TcpListen {
    local: LocalAddr,
}

#[derive(Clone, Debug)]
pub struct Tcp<State>
where
    State: TcpState + Clone,
{
    local: LocalAddr,
    remote: RemoteAddr,
    tcb: Tcb,
    retransmission: VecDeque<TcpPacket<Vec<u8>>>,
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

    pub fn recv_syn(self, remote: Ipv4Address, syn: &Syn) -> (Tcp<SynRcvd>, SynAck) {
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
            rcv_wnd: 1000,

            // strictly speaking these should be set only when we get the first ACK
            // but let's set them to sensible values immediately
            // so they don't have to be Option<_>.
            snd_wl1: syn.seq_number,
            snd_wl2: iss,

            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: syn.window_len,
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
        tcb.snd_nxt += resp.segment_len();

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
                retransmission: Default::default(),
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
    fn filter(&self, _remote_addr: Ipv4Address, packet: &TcpPacket<T>) -> bool {
        // This is a bit janky but it works for now
        if packet.syn() == true
            && packet.ack() == false
            && packet.rst() == false
            && packet.fin() == false
            && packet.psh() == false
        {
            true
        } else {
            warn!("ignoring non-SYN in Listen state");
            false
        }
    }
}

impl<T, U> ChannelFilter<TcpPacket<U>> for Tcp<T>
where
    T: TcpState + Clone,
    U: AsRef<[u8]>,
{
    fn filter(&self, remote_addr: Ipv4Address, packet: &TcpPacket<U>) -> bool {
        if remote_addr != self.remote.addr {
            info!("ignoring packet to wrong address");
            return false;
        }
        if packet.dst_port() == self.local.port && packet.src_port() == self.remote.port {
            true
        } else {
            info!("ignoring packet to wrong port");
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
    T: TcpState + 'static + Clone,
{
    pub fn remote_addr(&self) -> Ipv4Address {
        self.remote.addr
    }

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

        self.tcb.snd_nxt += repr.segment_len();

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

    fn build_reset(&self) -> Rst {
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            control: TcpControl::Rst,
            seq_number: self.tcb.snd_nxt,
            ack_number: None,
            window_len: self.tcb.rcv_wnd,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        };

        let mut buf = vec![0; repr.buffer_len()];

        repr.emit(
            &mut TcpPacket::new_unchecked(&mut buf),
            &IpAddress::from(self.local.addr),
            &IpAddress::from(self.remote.addr),
            &self.local.checksum_caps,
        );

        Rst {
            packet: TcpPacket::new_unchecked(buf),
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

        if seg.seq_number > self.tcb.rcv_nxt {
            warn!("gap before received segment, ignoring");
            return Reaction::Acceptable(None, None);
        }

        let payload = seg
            .payload
            .get(self.tcb.rcv_nxt - seg.seq_number..)
            .unwrap_or(&[]);
        // let's not worry about payloads that are too long

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
                        self.tcb.snd_wl1 = seg.seq_number;
                        self.tcb.snd_wl2 = ack_number;
                        return Reaction::Acceptable(None, None);
                    } else {
                        return Reaction::Reset(Some(self.build_reset()));
                    }
                }

                if self.tcb.snd_una < ack_number && ack_number <= self.tcb.snd_nxt {
                    self.tcb.snd_una = ack_number;
                    // pop all acknowledged segments from the retransmission queue
                    while let Some(rt) = self.retransmission.front() {
                        if rt.seq_number() + rt.segment_len() <= ack_number {
                            self.retransmission.pop_front();
                        } else {
                            break;
                        }
                    }
                } else if ack_number > self.tcb.snd_nxt {
                    return Reaction::NotAcceptable(Some(self.build_ack(&[])));
                }

                // SND.UNA =< SEG.ACK =< SND.NXT
                if self.tcb.snd_una <= ack_number && ack_number <= self.tcb.snd_nxt {
                    if self.tcb.snd_wl1 < seg.seq_number
                        || (self.tcb.snd_wl1 == seg.seq_number && self.tcb.snd_wl2 <= ack_number)
                    {
                        self.tcb.snd_wnd = seg.window_len;
                        self.tcb.snd_wl1 = seg.seq_number;
                        self.tcb.snd_wl2 = ack_number;
                    }
                }

                // ignore URG

                self.tcb.rcv_nxt = seg.seq_number + seg.segment_len();
                Reaction::Acceptable(
                    if seg.segment_len() > 0 {
                        Some(self.build_ack(&[]))
                    } else {
                        None
                    },
                    if payload.len() > 0 {
                        Some(payload)
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

    pub fn for_picker(&self) -> Tcp<_ForPicker> {
        let clone = (*self).clone();
        clone.transition()
    }
}

trait Transition<T> {
    fn transition(self) -> T;
}

impl<T, U> Transition<Tcp<T>> for Tcp<U>
where
    T: TcpState + Clone,
    U: TcpState + Clone,
{
    fn transition(self) -> Tcp<T> {
        Tcp {
            local: self.local,
            remote: self.remote,
            tcb: self.tcb,
            retransmission: self.retransmission,
            _marker: PhantomData,
        }
    }
}

impl Tcp<SynRcvd> {
    pub fn recv_ack(mut self, ack: &Ack) -> Tcp<Established> {
        let ack = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(None, None) => {
                info!("SynRcvd: got ack: {:?}", ack);
                self.transition()
            }
            Reaction::Acceptable(_, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }
}

impl Tcp<Established> {
    pub fn recv<'a>(&mut self, ack: &'a Ack) -> Reaction<'a> {
        let ack: TcpRepr<'a> = self.parse(ack);
        self.accept(&ack)
    }

    pub fn recv_fin(mut self, fin: &FinAck) -> (Tcp<CloseWait>, Ack) {
        let fin = self.parse(fin);
        match self.accept(&fin) {
            Reaction::Acceptable(Some(ack), None) => (self.transition(), ack),
            Reaction::Acceptable(_, _) => todo!(),
            Reaction::NotAcceptable(_) => todo!(),
            Reaction::Reset(_) => todo!(),
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Ack {
        let ack = self.build_ack(data);
        self.retransmission.push_back(ack.packet.clone());
        ack
    }

    pub fn close(mut self) -> (Tcp<FinWait1>, FinAck) {
        let fin = self.build_fin();
        (self.transition(), fin)
    }

    pub fn retransmission(&self) -> Option<Ack> {
        warn!("retransmission");
        self.retransmission
            .get(0)
            .map(|p| Ack { packet: p.clone() })
    }
}

impl Tcp<FinWait1> {
    pub fn recv(mut self, ack: &Ack) -> Tcp<FinWait2> {
        let ack = self.parse(ack);
        match self.accept(&ack) {
            Reaction::Acceptable(None, None) => self.transition(),
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
        (self.transition(), fin)
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

impl Tcp<_ForPicker> {
    pub fn acceptable<T>(mut self, packet: &TcpPacket<T>) -> Reaction
    where
        T: AsRef<[u8]>,
    {
        let packet = TcpRepr::parse(
            &TcpPacket::new_unchecked(packet.as_ref()),
            &IpAddress::from(self.remote.addr),
            &IpAddress::from(self.local.addr),
            &self.local.checksum_caps,
        )
        .unwrap();
        self.accept(&packet)
    }
}
