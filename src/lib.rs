pub mod cb;
pub mod smol_channel;
pub mod smol_lower;
pub mod st;
pub mod st_macros;
pub mod tcp;

use paste::paste;
use std::marker::PhantomData;

use crate::cb::{Close, Connected, Data, Open, TcbCreated};
use crate::smol_channel::{Ack, Syn, SynAck};
use crate::st::{Action, End, OfferOne, OfferTwo, Role, SelectOne, SelectTwo};
use crate::st_macros::{Rec, Role, St};

Role!(pub RoleServerSystem);
Role!(pub RoleServerUser);
Role!(pub RoleClientSystem);

Rec!(pub ServerSystemCommLoop, [
    (RoleClientSystem & Ack).
    (RoleClientSystem + Ack /* empty */).
    (RoleServerUser + Data).
    (RoleServerUser & {
        Data.
            (RoleClientSystem + Ack).
            (RoleClientSystem & Ack /* empty ack */).
            ServerSystemCommLoop,
        Close. /* TODO close sequence */ end
    })
]);

pub type ServerSystemSessionType = St![
    (RoleServerUser & Open).
    (RoleServerUser + TcbCreated).
    (RoleClientSystem & Syn).
    (RoleClientSystem + SynAck).
    (RoleClientSystem & Ack).
    (RoleServerUser + Connected).
    ServerSystemCommLoop
];

Rec!(pub ServerUserCommLoop, [
    (RoleServerSystem & Data).
    (RoleServerSystem + {
        Data.ServerUserCommLoop,
        Close.end
    })
]);

pub type ServerUserSessionType = St![
    (RoleServerSystem + Open).
    (RoleServerSystem & TcbCreated).
    (RoleServerSystem & Connected).
    ServerUserCommLoop
];
