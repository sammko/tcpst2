pub mod cb;
pub mod smol_channel;
pub mod smol_lower;
pub mod st;

use std::marker::PhantomData;

use crate::cb::{Connected, Data, Open, TcbCreated};
use crate::smol_channel::{Ack, Syn, SynAck};
use crate::st::{Action, OfferOne, Role, SelectOne};

type SsclInner = OfferOne<
    RoleClientSystem,
    Ack, // empty
    OfferOne<
        RoleClientSystem,
        Ack, // with data
        SelectOne<
            RoleServerUser,
            Data,
            OfferOne<RoleServerUser, Data, SelectOne<RoleClientSystem, Ack, ServerSystemCommLoop>>,
        >,
    >,
>;
pub struct ServerSystemCommLoop(PhantomData<SsclInner>);

impl ServerSystemCommLoop {
    pub fn inner(self) -> SsclInner {
        SsclInner::new()
    }
}

impl Action for ServerSystemCommLoop {
    fn new() -> Self {
        Self(PhantomData)
    }
}

pub type ServerSystemSessionType = OfferOne<
    RoleServerUser,
    Open,
    SelectOne<
        RoleServerUser,
        TcbCreated,
        OfferOne<
            RoleClientSystem,
            Syn,
            SelectOne<
                RoleClientSystem,
                SynAck,
                OfferOne<
                    RoleClientSystem,
                    Ack,
                    SelectOne<RoleServerUser, Connected, ServerSystemCommLoop>,
                >,
            >,
        >,
    >,
>;

type SuclInner =
    OfferOne<RoleServerSystem, Data, SelectOne<RoleServerSystem, Data, ServerUserCommLoop>>;

pub struct ServerUserCommLoop(PhantomData<SuclInner>);

impl ServerUserCommLoop {
    pub fn inner(self) -> SuclInner {
        SuclInner::new()
    }
}

impl Action for ServerUserCommLoop {
    fn new() -> Self {
        ServerUserCommLoop(PhantomData)
    }
}

pub type ServerUserSessionType = SelectOne<
    RoleServerSystem,
    Open,
    OfferOne<
        RoleServerSystem,
        TcbCreated,
        OfferOne<RoleServerSystem, Connected, ServerUserCommLoop>,
    >,
>;

macro_rules! role {
    (pub $name:ident) => {
        pub struct $name;
        impl Role for $name {}
    };
}

role!(pub RoleServerSystem);
role!(pub RoleServerUser);
role!(pub RoleClientSystem);
