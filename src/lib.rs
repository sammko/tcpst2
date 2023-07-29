pub mod cb;
pub mod smol_channel;
pub mod smol_lower;
pub mod st;
pub mod st_macros;
pub mod tcp;

use paste::paste;
use std::marker::PhantomData;

use crate::cb::{Close, Connected, Data, Open, TcbCreated};
use crate::smol_channel::{Ack, FinAck, Syn, SynAck};
use crate::st::{Action, End, OfferOne, OfferTwo, Role, SelectOne, SelectTwo};
use crate::st_macros::{Rec, Role, St};

Role!(pub RoleServerSystem);
Role!(pub RoleServerUser);
Role!(pub RoleClientSystem);

pub type ServerSystemFinWait1 = St![(RoleClientSystem & Ack/* ACK of FIN */).ServerSystemFinWait2];

Rec!(pub ServerSystemFinWait2, [
    (RoleClientSystem & {
        Ack. // data we don't care about
            (RoleClientSystem + Ack).
            ServerSystemFinWait2,
        FinAck. // other peer is closing as well
            (RoleClientSystem + Ack).
            end
    })
]);

Rec!(pub ServerSystemCommLoop, [
    (RoleClientSystem & Ack).
    (RoleClientSystem + Ack /* empty */).
    (RoleServerUser + Data).
    (RoleServerUser & {
        Data.
            (RoleClientSystem + Ack).
            (RoleClientSystem & Ack /* empty ack */).
            ServerSystemCommLoop,
        Close.
            (RoleClientSystem + FinAck).
            ServerSystemFinWait1
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
