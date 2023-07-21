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

// Supporting traits

pub trait Action: Send {
    fn new() -> Self
    where
        Self: Sized;
}

pub trait Role {}

pub trait Message: Send {
    fn to_net_representation(self) -> Vec<u8>;
    fn from_net_representation(packet: Vec<u8>) -> Self;
}

// Session action types

pub struct OfferOne<R, M, A>
where
    M: Message,
    A: Action,
    R: Role,
{
    phantom: PhantomData<(R, M, A)>,
}

impl<R, M, A> Action for OfferOne<R, M, A>
where
    M: Message,
    A: Action,
    R: Role + std::marker::Send,
{
    fn new() -> Self
    where
        Self: Sized,
    {
        OfferOne {
            phantom: PhantomData,
        }
    }
}

pub struct SelectOne<R, M, A>
where
    M: Message,
    A: Action,
    R: Role,
{
    phantom: PhantomData<(R, M, A)>,
}

impl<R, M, A> Action for SelectOne<R, M, A>
where
    M: Message,
    A: Action,
    R: Role + std::marker::Send,
{
    fn new() -> Self
    where
        Self: Sized,
    {
        SelectOne {
            phantom: PhantomData,
        }
    }
}

pub struct OfferTwo<R, M1, M2, A1, A2>
where
    R: Role,
    M1: Message,
    M2: Message,
    A1: Action,
    A2: Action,
{
    phantom: PhantomData<(R, M1, M2, A1, A2)>,
}

impl<R, M1, M2, A1, A2> Action for OfferTwo<R, M1, M2, A1, A2>
where
    R: Role + std::marker::Send,
    M1: Message,
    M2: Message,
    A1: Action,
    A2: Action,
{
    fn new() -> Self
    where
        Self: Sized,
    {
        OfferTwo {
            phantom: PhantomData::default(),
        }
    }
}

pub enum Branch<L, R> {
    Left(L),
    Right(R),
}

pub struct SelectTwo<R, M1, M2, A1, A2>
where
    R: Role,
    M1: Message,
    M2: Message,
    A1: Action,
    A2: Action,
{
    phantom: PhantomData<(R, M1, M2, A1, A2)>,
}

impl<R, M1, M2, A1, A2> Action for SelectTwo<R, M1, M2, A1, A2>
where
    R: Role + std::marker::Send,
    M1: Message,
    M2: Message,
    A1: Action,
    A2: Action,
{
    fn new() -> Self
    where
        Self: Sized,
    {
        SelectTwo {
            phantom: PhantomData::default(),
        }
    }
}

pub struct End {}

impl Action for End {
    fn new() -> Self
    where
        Self: Sized,
    {
        End {}
    }
}

pub trait SessionTypedChannel<R1, R2> {
    #[must_use]
    fn offer_one<M, A>(&mut self, _o: OfferOne<R2, M, A>) -> (M, A)
    where
        M: Message + 'static,
        A: Action + 'static,
        R1: Role,
        R2: Role;

    #[must_use]
    fn select_one<M, A>(&mut self, _o: SelectOne<R2, M, A>, message: M) -> A
    where
        M: Message,
        A: Action,
        R1: Role,
        R2: Role;

    #[must_use]
    fn offer_two<M1, M2, A1, A2>(
        &mut self,
        _o: OfferTwo<R2, M1, M2, A1, A2>,
        picker: Box<dyn Fn() -> bool>,
    ) -> Branch<(M1, A1), (M2, A2)>
    where
        R1: Role,
        R2: Role,
        M1: Message + 'static,
        M2: Message + 'static,
        A1: Action,
        A2: Action;

    #[must_use]
    fn select_left<M1, M2, A1, A2>(&mut self, _o: SelectTwo<R2, M1, M2, A1, A2>, message: M1) -> A1
    where
        R1: Role,
        R2: Role,
        M1: Message + 'static,
        M2: Message + 'static,
        A1: Action,
        A2: Action;

    #[must_use]
    fn select_right<M1, M2, A1, A2>(
        &mut self,
        _o: SelectTwo<R2, M1, M2, A1, A2>,
        message: M2,
    ) -> A2
    where
        R1: Role,
        R2: Role,
        M1: Message + 'static,
        M2: Message + 'static,
        A1: Action,
        A2: Action;

    fn close(self, end: End);
}
