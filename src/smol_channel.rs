use std::marker::PhantomData;

use smoltcp::{
    time::{Duration, Instant},
    wire::{Ipv4Address, TcpPacket},
};

use crate::{
    smol_lower::{RecvError, SmolLower},
    st::{Action, Branch, End, Message, OfferOne, OfferTwo, Role, SelectOne, SelectTwo},
    tcp::ChannelFilter,
};

pub trait SmolMessage: Message {
    fn from_packet(buf: TcpPacket<Vec<u8>>) -> Self;
    fn packet(&self) -> &TcpPacket<Vec<u8>>;
}

pub struct SmolChannel<'a, R1, R2>
where
    R1: Role,
    R2: Role,
{
    lower: SmolLower<'a>,
    phantom: PhantomData<(R1, R2)>,
}

impl<'a, R1, R2> SmolChannel<'a, R1, R2>
where
    R1: Role,
    R2: Role,
{
    pub fn new(lower: SmolLower<'a>) -> Self {
        Self {
            lower,
            phantom: PhantomData,
        }
    }

    pub fn offer_one_with_addr<M, A, F>(
        &mut self,
        _o: OfferOne<R2, M, A>,
        filter: &F,
    ) -> (Ipv4Address, M, A)
    where
        M: SmolMessage,
        A: Action,
        F: ChannelFilter<TcpPacket<Vec<u8>>>,
    {
        let (addr, buf) = loop {
            let (addr, buf) = self.lower.recv(None).expect("recv failed");
            if filter.filter(addr, &buf) {
                break (addr, buf);
            }
        };
        (addr, M::from_packet(buf), A::new())
    }

    pub fn offer_one_filtered<M, A, F>(&mut self, o: OfferOne<R2, M, A>, filter: &F) -> (M, A)
    where
        M: SmolMessage,
        A: Action,
        F: ChannelFilter<TcpPacket<Vec<u8>>>,
    {
        let (_, m, a) = self.offer_one_with_addr(o, filter);
        (m, a)
    }

    pub fn offer_two_filtered<M1, M2, A1, A2, P, F>(
        &mut self,
        _o: OfferTwo<R2, M1, M2, A1, A2>,
        picker: P,
        filter: &F,
        timeout: Option<Duration>,
    ) -> Branch<(M1, A1), (M2, A2)>
    where
        R1: Role,
        R2: Role,
        M1: Message,
        M2: Message,
        A1: Action,
        A2: Action,
        P: FnOnce(Option<TcpPacket<Vec<u8>>>) -> Branch<M1, M2>,
        F: ChannelFilter<TcpPacket<Vec<u8>>>,
    {
        let deadline = timeout.map(|t| Instant::now() + t);
        let buf = loop {
            let (addr, buf) = match self.lower.recv(deadline) {
                Ok(m) => m,
                Err(RecvError::Timeout) => break None,
                Err(_) => panic!("recv failed"),
            };
            if filter.filter(addr, &buf) {
                break Some(buf);
            }
        };
        match picker(buf) {
            Branch::Left(m) => Branch::Left((m, A1::new())),
            Branch::Right(m) => Branch::Right((m, A2::new())),
        }
    }

    pub fn select_one<M, A>(&mut self, _o: SelectOne<R2, M, A>, to: Ipv4Address, message: M) -> A
    where
        M: SmolMessage,
        A: Action,
        R1: Role,
        R2: Role,
    {
        let buf = message.packet().as_ref();
        self.lower.send(to, &buf).expect("send failed");
        A::new()
    }

    pub fn select_left<M1, M2, A1, A2>(
        &mut self,
        _o: SelectTwo<R2, M1, M2, A1, A2>,
        to: Ipv4Address,
        message: M1,
    ) -> A1
    where
        R1: Role,
        R2: Role,
        M1: SmolMessage,
        M2: SmolMessage,
        A1: Action,
        A2: Action,
    {
        let buf = message.packet().as_ref();
        self.lower.send(to, &buf).expect("send failed");
        A1::new()
    }

    pub fn select_right<M1, M2, A1, A2>(
        &mut self,
        _o: SelectTwo<R2, M1, M2, A1, A2>,
        to: Ipv4Address,
        message: M2,
    ) -> A2
    where
        R1: Role,
        R2: Role,
        M1: SmolMessage,
        M2: SmolMessage,
        A1: Action,
        A2: Action,
    {
        let buf = message.packet().as_ref();
        self.lower.send(to, &buf).expect("send failed");
        A2::new()
    }

    pub fn close(self, _end: End) {
        drop(self)
    }
}

macro_rules! check_flag {
    ($p:ident, +, $flag:ident) => {
        assert!($p.$flag(), "flag {} not set", stringify!($flag));
    };
    ($p:ident, -, $flag:ident) => {
        assert!(!$p.$flag(), "flag {} set", stringify!($flag));
    };
}

macro_rules! smol_message {
    ($name:ident $({$($tag:tt $flag:ident)* $(,)?})*) => {
        pub struct $name {
            packet: TcpPacket<Vec<u8>>,
        }
        impl Message for $name {}
        impl SmolMessage for $name {
            fn packet(&self) -> &TcpPacket<Vec<u8>> {
                &self.packet
            }

            fn from_packet(packet: TcpPacket<Vec<u8>>) -> Self {
                $($(check_flag!(packet, $tag, $flag);)*)*
                $name { packet }
            }
        }
        impl From<TcpPacket<Vec<u8>>> for $name {
            fn from(packet: TcpPacket<Vec<u8>>) -> Self {
                Self::from_packet(packet)
            }
        }
    };
}

smol_message!(Syn { +syn -ack -fin -rst });
smol_message!(SynAck { +syn +ack -fin -rst });
smol_message!(Ack { -syn +ack -fin -rst });
smol_message!(FinAck { -syn +ack +fin -rst });
smol_message!(Rst { -syn -ack -fin +rst });
