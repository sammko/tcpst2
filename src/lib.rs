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
use crate::st::{Action, End, NestRole, Nested, OfferOne, OfferTwo, Role, SelectOne, SelectTwo};
use crate::st_macros::{Nest, Rec, Role, St};

Role!(pub RoleServerSystem);
Role!(pub RoleServerUser);
Role!(pub RoleClientSystem);

pub type ServerSystemFinWait1 = St![
    (RoleClientSystem & Ack/* ACK of FIN. TODO we should handle other ACKs here as well maybe */)
        .ServerSystemFinWait2
];

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

Rec!(pub ServerSystemCloseWait, [
    (RoleServerUser & {
        Data.
            (RoleClientSystem + Ack).
            (RoleClientSystem & Ack /* empty ack */).
            ServerSystemCloseWait,
        Close.
            (RoleClientSystem + FinAck).
            (RoleClientSystem & Ack).
            end
    })
]);

Rec!(pub ServerSystemCommLoop, [
    (RoleClientSystem & {
        Ack. // acceptable
            (RoleClientSystem + Ack /* empty */).
            (RoleServerUser + Data).
            (RoleServerUser & {
                Data.
                    (RoleClientSystem + Ack).
                    (RoleClientSystem & Ack /* empty ack */). // TODO we should make this another branch of the top-level offer
                    ServerSystemCommLoop,
                Close.
                    (RoleClientSystem + FinAck).
                    ServerSystemFinWait1
            }),
        FinAck.
            (RoleClientSystem + Ack /* we ACK the FIN */).
            (RoleServerUser + Close).
            ServerSystemCloseWait,
        Ack. // unacceptable
            (RoleClientSystem + Ack /* challenge */).
            ServerSystemCommLoop
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

Rec!(pub ServerUserCloseWait, [
    (RoleServerSystem + {
        Data.ServerUserCloseWait,
        Close.end
    })
]);

Rec!(pub ServerUserCommLoop, [
    (RoleServerSystem & {
        Data.
            (RoleServerSystem + {
                Data.ServerUserCommLoop,
                Close.end
            }),
        Close.ServerUserCloseWait
    })
]);

pub type ServerUserSessionType = St![
    (RoleServerSystem + Open).
    (RoleServerSystem & TcbCreated).
    (RoleServerSystem & Connected).
    ServerUserCommLoop
];
