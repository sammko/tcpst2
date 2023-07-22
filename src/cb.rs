/**
 * Copyright 2023, Ivan Nikitin.
 * This file is part of TCP-ST.
 *
 * TCP-ST is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * TCP-ST is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with TCP-ST.
 * If not, see <https://www.gnu.org/licenses/>.
 *
 */
use std::marker::PhantomData;

use crossbeam_channel::{Receiver, Sender};

use crate::{
    st::{
        Action, Branch, Choice, End, Message, OfferOne, OfferTwo, Role, SelectOne, SelectTwo,
        SessionTypedChannel,
    },
    st_macros::empty_message,
};

/// [CrossBeamRoleChannel] is a session-typed communication channel that uses crossbeam channels under the hood.
/// [CrossBeamRoleChannel] behaves as any other session-typed channels and implements [SessionTypedChannel].
#[derive(Clone)]
pub struct CrossBeamRoleChannel<R1, R2>
where
    R1: Role,
    R2: Role,
{
    pub send: Sender<Vec<u8>>,
    pub recv: Receiver<Vec<u8>>,
    pub phantom: PhantomData<(R1, R2)>,
}

impl<R1, R2> CrossBeamRoleChannel<R1, R2>
where
    R1: Role,
    R2: Role,
{
    pub fn new(send: Sender<Vec<u8>>, recv: Receiver<Vec<u8>>) -> Self {
        CrossBeamRoleChannel {
            send,
            recv,
            phantom: PhantomData::default(),
        }
    }
}

impl<R1, R2> SessionTypedChannel<R1, R2> for CrossBeamRoleChannel<R1, R2>
where
    R1: Role,
    R2: Role,
{
    type TransportType = Vec<u8>;

    fn offer_one<M, A>(&mut self, _o: OfferOne<R2, M, A>) -> (M, A)
    where
        M: Message + 'static,
        A: Action + 'static,
        R1: Role,
        R2: Role,
    {
        (
            M::from_net_representation(self.recv.recv().unwrap()),
            A::new(),
        )
    }

    fn select_one<M, A>(&mut self, _o: SelectOne<R2, M, A>, message: M) -> A
    where
        M: Message,
        A: Action,
        R1: Role,
        R2: Role,
    {
        self.send.send(message.to_net_representation()).unwrap();
        A::new()
    }

    fn offer_two<M1, M2, A1, A2>(
        &mut self,
        _o: OfferTwo<R2, M1, M2, A1, A2>,
        picker: Box<dyn Fn(&Self::TransportType) -> Choice>,
    ) -> Branch<(M1, A1), (M2, A2)>
    where
        R1: Role,
        R2: Role,
        M1: Message + 'static,
        M2: Message + 'static,
        A1: Action,
        A2: Action,
    {
        let data = self.recv.recv().unwrap();
        let choice = picker(&data);
        match choice {
            Choice::Left => Branch::Left((M1::from_net_representation(data), A1::new())),
            Choice::Right => Branch::Right((M2::from_net_representation(data), A2::new())),
        }
    }

    fn select_left<M1, M2, A1, A2>(&mut self, _o: SelectTwo<R2, M1, M2, A1, A2>, message: M1) -> A1
    where
        R1: Role,
        R2: Role,
        M1: Message + 'static,
        M2: Message + 'static,
        A1: Action,
        A2: Action,
    {
        self.send.send(message.to_net_representation()).unwrap();
        A1::new()
    }

    fn select_right<M1, M2, A1, A2>(&mut self, _o: SelectTwo<R2, M1, M2, A1, A2>, message: M2) -> A2
    where
        R1: Role,
        R2: Role,
        M1: Message + 'static,
        M2: Message + 'static,
        A1: Action,
        A2: Action,
    {
        self.send.send(message.to_net_representation()).unwrap();
        A2::new()
    }

    fn close(self, _end: End) {
        drop(self);
    }
}

empty_message!(Open);
empty_message!(TcbCreated);
empty_message!(Connected);
empty_message!(Close);

const MAGIC_DATA: u8 = 1;

pub struct Data {
    pub data: Vec<u8>,
}

impl Message for Data {
    fn to_net_representation(self) -> Vec<u8> {
        let mut data = vec![MAGIC_DATA];
        data.extend(self.data);
        data
    }

    fn from_net_representation(data: Vec<u8>) -> Self {
        Data {
            data: data[1..].to_vec(),
        }
    }
}
