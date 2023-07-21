use std::marker::PhantomData;

use smoltcp::wire::Ipv4Address;

use crate::{
    smol_lower::SmolLower,
    st::{Message, Role, SessionTypedChannel},
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
}

impl<R1, R2> SessionTypedChannel<R1, R2> for SmolChannel<'_, R1, R2>
where
    R1: Role,
    R2: Role,
{
    fn offer_one<M, A>(&mut self, _o: crate::st::OfferOne<R2, M, A>) -> (M, A)
    where
        M: crate::st::Message + 'static,
        A: crate::st::Action + 'static,
        R1: Role,
        R2: Role,
    {
        let (addr, buf) = self.lower.recv().expect("recv failed");
        assert_eq!(addr, self.remote_addr); // TODO handle multiple peers
        return (M::from_net_representation(buf), A::new());
    }

    fn select_one<M, A>(&mut self, _o: crate::st::SelectOne<R2, M, A>, message: M) -> A
    where
        M: crate::st::Message,
        A: crate::st::Action,
        R1: Role,
        R2: Role,
    {
        let buf = message.to_net_representation();
        self.lower
            .send(self.remote_addr, &buf)
            .expect("send failed");
        return A::new();
    }

    fn offer_two<M1, M2, A1, A2>(
        &mut self,
        _o: crate::st::OfferTwo<R2, M1, M2, A1, A2>,
        _picker: Box<dyn Fn() -> bool>,
    ) -> crate::st::Branch<(M1, A1), (M2, A2)>
    where
        R1: Role,
        R2: Role,
        M1: crate::st::Message + 'static,
        M2: crate::st::Message + 'static,
        A1: crate::st::Action,
        A2: crate::st::Action,
    {
        todo!()
    }

    fn select_left<M1, M2, A1, A2>(
        &mut self,
        _o: crate::st::SelectTwo<R2, M1, M2, A1, A2>,
        _message: M1,
    ) -> A1
    where
        R1: Role,
        R2: Role,
        M1: crate::st::Message + 'static,
        M2: crate::st::Message + 'static,
        A1: crate::st::Action,
        A2: crate::st::Action,
    {
        todo!()
    }

    fn select_right<M1, M2, A1, A2>(
        &mut self,
        _o: crate::st::SelectTwo<R2, M1, M2, A1, A2>,
        _message: M2,
    ) -> A2
    where
        R1: Role,
        R2: Role,
        M1: crate::st::Message + 'static,
        M2: crate::st::Message + 'static,
        A1: crate::st::Action,
        A2: crate::st::Action,
    {
        todo!()
    }

    fn close(self, _end: crate::st::End) {
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
