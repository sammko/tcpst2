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

#[derive(Copy, Clone)]
pub struct End {}

impl Action for End {
    fn new() -> Self
    where
        Self: Sized,
    {
        End {}
    }
}

pub struct NestRole;

impl Role for NestRole {}

pub enum Nested<M1, M2> {
    Left(M1),
    Right(M2),
}
impl<M1, M2> Message for Nested<M1, M2>
where
    M1: Message,
    M2: Message,
{
}

pub fn nested_offer_two<M1, M2, A1, A2>(
    _o: OfferTwo<NestRole, M1, M2, A1, A2>,
    nested: Nested<M1, M2>,
) -> Branch<(M1, A1), (M2, A2)>
where
    M1: Message,
    M2: Message,
    A1: Action,
    A2: Action,
{
    match nested {
        Nested::Left(m1) => Branch::Left((m1, A1::new())),
        Nested::Right(m2) => Branch::Right((m2, A2::new())),
    }
}

pub struct Timeout;
impl Message for Timeout {}
