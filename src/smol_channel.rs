use std::marker::PhantomData;

use smoltcp::wire::{Ipv4Address, TcpPacket};

use crate::{
    smol_lower::SmolLower,
    st::{
        Action, Branch, Choice, End, Message, OfferOne, OfferTwo, Role, SelectOne, SelectTwo,
        SessionTypedChannel,
    },
    tcp::ChannelFilter,
};

pub struct SmolChannel<'a, R1, R2>
where
    R1: Role,
    R2: Role,
{
    lower: SmolLower<'a>,
    remote_addr: Ipv4Address,
    phantom: PhantomData<(R1, R2)>,
}

impl<'a, R1, R2> SmolChannel<'a, R1, R2>
where
    R1: Role,
    R2: Role,
{
    pub fn new(lower: SmolLower<'a>, remote_addr: Ipv4Address) -> Self {
        Self {
            lower,
            remote_addr,
            phantom: PhantomData,
        }
    }

    pub fn offer_one_filtered<M, A, F>(&mut self, _o: OfferOne<R2, M, A>, filter: &F) -> (M, A)
    where
        M: Message,
        A: Action,
        F: ChannelFilter<<Self as SessionTypedChannel<R1, R2>>::TransportType>,
    {
        let (addr, buf) = loop {
            let (addr, buf) = self.lower.recv().expect("recv failed");
            if filter.filter(&buf) {
                break (addr, buf);
            }
        };
        assert_eq!(addr, self.remote_addr); // TODO handle multiple peers
        (M::from_net_representation(buf), A::new())
    }

    pub fn offer_two_filtered<M1, M2, A1, A2, P, F>(
        &mut self,
        _o: OfferTwo<R2, M1, M2, A1, A2>,
        picker: P,
        filter: &F,
    ) -> Branch<(M1, A1), (M2, A2)>
    where
        R1: Role,
        R2: Role,
        M1: Message,
        M2: Message,
        A1: Action,
        A2: Action,
        P: FnOnce(&<Self as SessionTypedChannel<R1, R2>>::TransportType) -> Choice,
        F: ChannelFilter<<Self as SessionTypedChannel<R1, R2>>::TransportType>,
    {
        let (addr, buf) = loop {
            let (addr, buf) = self.lower.recv().expect("recv failed");
            if filter.filter(&buf) {
                break (addr, buf);
            }
        };
        assert_eq!(addr, self.remote_addr); // TODO handle multiple peers
        match picker(&buf) {
            Choice::Left => Branch::Left((M1::from_net_representation(buf), A1::new())),
            Choice::Right => Branch::Right((M2::from_net_representation(buf), A2::new())),
        }
    }
}

impl<R1, R2> SessionTypedChannel<R1, R2> for SmolChannel<'_, R1, R2>
where
    R1: Role,
    R2: Role,
{
    type TransportType = Vec<u8>;

    fn offer_one<M, A>(&mut self, _o: OfferOne<R2, M, A>) -> (M, A)
    where
        M: Message,
        A: Action,
        R1: Role,
        R2: Role,
    {
        let (addr, buf) = self.lower.recv().expect("recv failed");
        assert_eq!(addr, self.remote_addr); // TODO handle multiple peers
        (M::from_net_representation(buf), A::new())
    }

    fn select_one<M, A>(&mut self, _o: SelectOne<R2, M, A>, message: M) -> A
    where
        M: Message,
        A: Action,
        R1: Role,
        R2: Role,
    {
        let buf = message.to_net_representation();
        self.lower
            .send(self.remote_addr, &buf)
            .expect("send failed");
        A::new()
    }

    fn offer_two<M1, M2, A1, A2, F>(
        &mut self,
        _o: OfferTwo<R2, M1, M2, A1, A2>,
        picker: F,
    ) -> Branch<(M1, A1), (M2, A2)>
    where
        R1: Role,
        R2: Role,
        M1: Message,
        M2: Message,
        A1: Action,
        A2: Action,
        F: FnOnce(&Self::TransportType) -> Choice,
    {
        let (addr, buf) = self.lower.recv().expect("recv failed");
        assert_eq!(addr, self.remote_addr); // TODO handle multiple peers
        match picker(&buf) {
            Choice::Left => Branch::Left((M1::from_net_representation(buf), A1::new())),
            Choice::Right => Branch::Right((M2::from_net_representation(buf), A2::new())),
        }
    }

    fn select_left<M1, M2, A1, A2>(&mut self, _o: SelectTwo<R2, M1, M2, A1, A2>, message: M1) -> A1
    where
        R1: Role,
        R2: Role,
        M1: Message,
        M2: Message,
        A1: Action,
        A2: Action,
    {
        let buf = message.to_net_representation();
        self.lower
            .send(self.remote_addr, &buf)
            .expect("send failed");
        A1::new()
    }

    fn select_right<M1, M2, A1, A2>(&mut self, _o: SelectTwo<R2, M1, M2, A1, A2>, message: M2) -> A2
    where
        R1: Role,
        R2: Role,
        M1: Message,
        M2: Message,
        A1: Action,
        A2: Action,
    {
        let buf = message.to_net_representation();
        self.lower
            .send(self.remote_addr, &buf)
            .expect("send failed");
        A2::new()
    }

    fn close(self, _end: End) {
        drop(self)
    }
}

/// [Syn] is the specific message type for a packet with
/// the SYN flag set. We assume a well-behaved parser and
/// leave the parsing implementation to the user. Hence,
/// this demonstration has an extremely simplistic layout of
/// message structs and does **no** error handling.
/// Hence, it is possible to construct a [Syn] message out of
/// a wrong packet. This should ideally be handled by checking
/// that correct flags are set and returning errors.
pub struct Syn {
    pub packet: Vec<u8>,
}

impl Message for Syn {
    fn to_net_representation(self) -> Vec<u8> {
        self.packet
    }

    fn from_net_representation(packet: Vec<u8>) -> Self {
        Syn { packet }
    }
}

/// [SynAck] is the specific message type for a packet with
/// the SYN flag set. We assume a well-behaved parser and
/// leave the parsing implementation to the user. Hence,
/// this demonstration has an extremely simplistic layout of
/// message structs and does **no** error handling.
/// Hence, it is possible to construct a [SynAck] message out of
/// a wrong packet. This should ideally be handled by checking
/// that correct flags are set and returning errors.
pub struct SynAck {
    pub packet: Vec<u8>,
}

impl Message for SynAck {
    fn to_net_representation(self) -> Vec<u8> {
        self.packet
    }

    fn from_net_representation(packet: Vec<u8>) -> Self {
        SynAck { packet }
    }
}

/// [Ack] is the specific message type for a packet with
/// the SYN flag set. We assume a well-behaved parser and
/// leave the parsing implementation to the user. Hence,
/// this demonstration has an extremely simplistic layout of
/// message structs and does **no** error handling.
/// Hence, it is possible to construct a [Ack] message out of
/// a wrong packet. This should ideally be handled by checking
/// that correct flags are set and returning errors.
pub struct Ack {
    pub packet: Vec<u8>,
}

impl Message for Ack {
    fn to_net_representation(self) -> Vec<u8> {
        self.packet
    }

    fn from_net_representation(packet: Vec<u8>) -> Self {
        Ack { packet }
    }
}

/// [FinAck] is the specific message type for a packet with
/// the SYN flag set. We assume a well-behaved parser and
/// leave the parsing implementation to the user. Hence,
/// this demonstration has an extremely simplistic layout of
/// message structs and does **no** error handling.
/// Hence, it is possible to construct a [FinAck] message out of
/// a wrong packet. This should ideally be handled by checking
/// that correct flags are set and returning errors.
pub struct FinAck {
    pub packet: Vec<u8>,
}

impl Message for FinAck {
    fn to_net_representation(self) -> Vec<u8> {
        self.packet
    }

    fn from_net_representation(packet: Vec<u8>) -> Self {
        FinAck { packet }
    }
}
