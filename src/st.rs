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

pub trait Action {
    fn new() -> Self;
}

pub trait Role {}

pub trait Message {
    // fn to_net_representation(self) -> Vec<u8>;
    // fn from_net_representation(packet: Vec<u8>) -> Self;
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
    R: Role,
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
    R: Role,
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
    R: Role,
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

pub enum Choice {
    Left,
    Right,
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
    R: Role,
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
