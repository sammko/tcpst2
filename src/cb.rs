use std::marker::PhantomData;

use crossbeam_channel::{Receiver, Sender};

use crate::st::{
    Action, Branch, Choice, End, Message, OfferOne, OfferTwo, Role, SelectOne, SelectTwo,
};

macro_rules! cb_message {
    ($name:ident, $data:ty) => {
        pub struct $name(pub $data);
        impl Message for $name {}
        impl CrossbeamMessage for $name {
            fn to_net_representation(self) -> NetRepresentation {
                NetRepresentation::$name(self)
            }
            fn from_net_representation(net: NetRepresentation) -> Self {
                if let NetRepresentation::$name(msg) = net {
                    msg
                } else {
                    panic!("Wrong message type")
                }
            }
        }
    };
    ($name:ident) => {
        cb_message!($name, ());
    };
}

pub enum NetRepresentation {
    Open(Open),
    TcbCreated(TcbCreated),
    Connected(Connected),
    Close(Close),
    Data(Data),
}

impl NetRepresentation {}

pub trait CrossbeamMessage: Message {
    fn to_net_representation(self) -> NetRepresentation;
    fn from_net_representation(packet: NetRepresentation) -> Self;
}

cb_message!(Open);
cb_message!(TcbCreated);
cb_message!(Connected);
cb_message!(Close);
cb_message!(Data, Vec<u8>);

/// [CrossBeamRoleChannel] is a session-typed communication channel that uses crossbeam channels under the hood.
/// [CrossBeamRoleChannel] behaves as any other session-typed channels and implements [SessionTypedChannel].
#[derive(Clone)]
pub struct CrossBeamRoleChannel<R1, R2>
where
    R1: Role,
    R2: Role,
{
    pub send: Sender<NetRepresentation>,
    pub recv: Receiver<NetRepresentation>,
    pub phantom: PhantomData<(R1, R2)>,
}

impl<R1, R2> CrossBeamRoleChannel<R1, R2>
where
    R1: Role,
    R2: Role,
{
    pub fn new(send: Sender<NetRepresentation>, recv: Receiver<NetRepresentation>) -> Self {
        CrossBeamRoleChannel {
            send,
            recv,
            phantom: PhantomData::default(),
        }
    }

    pub fn offer_one<M, A>(&mut self, _o: OfferOne<R2, M, A>) -> (M, A)
    where
        M: CrossbeamMessage,
        A: Action,
        R1: Role,
        R2: Role,
    {
        (
            M::from_net_representation(self.recv.recv().unwrap()),
            A::new(),
        )
    }

    pub fn select_one<M, A>(&mut self, _o: SelectOne<R2, M, A>, message: M) -> A
    where
        M: CrossbeamMessage,
        A: Action,
        R1: Role,
        R2: Role,
    {
        self.send.send(message.to_net_representation()).unwrap();
        A::new()
    }

    pub fn offer_two<M1, M2, A1, A2, F>(
        &mut self,
        _o: OfferTwo<R2, M1, M2, A1, A2>,
        picker: F,
    ) -> Branch<(M1, A1), (M2, A2)>
    where
        R1: Role,
        R2: Role,
        M1: CrossbeamMessage,
        M2: CrossbeamMessage,
        A1: Action,
        A2: Action,
        F: FnOnce(&NetRepresentation) -> Choice,
    {
        let data = self.recv.recv().unwrap();
        let choice = picker(&data);
        match choice {
            Choice::Left => Branch::Left((M1::from_net_representation(data), A1::new())),
            Choice::Right => Branch::Right((M2::from_net_representation(data), A2::new())),
        }
    }

    pub fn select_left<M1, M2, A1, A2>(
        &mut self,
        _o: SelectTwo<R2, M1, M2, A1, A2>,
        message: M1,
    ) -> A1
    where
        R1: Role,
        R2: Role,
        M1: CrossbeamMessage,
        M2: CrossbeamMessage,
        A1: Action,
        A2: Action,
    {
        self.send.send(message.to_net_representation()).unwrap();
        A1::new()
    }

    pub fn select_right<M1, M2, A1, A2>(
        &mut self,
        _o: SelectTwo<R2, M1, M2, A1, A2>,
        message: M2,
    ) -> A2
    where
        R1: Role,
        R2: Role,
        M1: CrossbeamMessage,
        M2: CrossbeamMessage,
        A1: Action,
        A2: Action,
    {
        self.send.send(message.to_net_representation()).unwrap();
        A2::new()
    }

    pub fn close(self, _end: End) {
        drop(self);
    }
}
