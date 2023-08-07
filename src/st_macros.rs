macro_rules! Role {
    (pub $name:ident) => {
        pub struct $name;
        impl Role for $name {}
    };
}
pub(crate) use Role;

macro_rules! Nest {
    [ $m1:ident, $m2:ident ] => { Nested<$m1, $m2> };
    [ $m1:ident, $($tail:ident),* ] => { Nested<$m1, Nest![$($tail),*]> };
}
pub(crate) use Nest;

macro_rules! St {
    [ end ] => { End };
    [ $cont:ident ] => { $cont };
    [ ($peer:ident + $msg:ident) $(.$tail:tt)* $(.)?] => {
        SelectOne<$peer, $msg, St![$($tail).*]>
    };
    [ ($peer:ident & $msg:ident) $(.$tail:tt)* $(.)?] => {
        OfferOne<$peer, $msg, St![$($tail).*]>
    };
    [ ($peer:ident + {
        $msg1:ident $(.$tail1:tt)*,
        $msg2:ident $(.$tail2:tt)*
    }) ] => {
        SelectTwo<$peer, $msg1, $msg2, St![$($tail1).*], St![$($tail2).*]>
    };
    [ ($peer:ident & {
        $msg1:ident $(.$tail1:tt)*,
        $msg2:ident $(.$tail2:tt)*
    }) ] => {
        OfferTwo<$peer, $msg1, $msg2, St![$($tail1).*], St![$($tail2).*]>
    };
    [ ($peer:ident & {
        $msg1:ident $(.$tail1:tt)*
        $(,$msgs:ident $(.$tails:tt)*)*$(,)?
    }) ] => {
        OfferTwo<$peer, $msg1, Nest![$($msgs),*], St![$($tail1).*], St![ (NestRole & {$($msgs $(.$tails)*),*}) ]>
    };
}
pub(crate) use St;

macro_rules! Rec {
    (pub $name:ident, $body:tt) => {
        paste! {
            pub struct $name(PhantomData<[<$name Inner>]>);
            type [<$name Inner>] = St!$body;
            impl $name {
                pub fn inner(self) -> [<$name Inner>] {
                    [<$name Inner>]::new()
                }
            }
        }
        impl Action for $name {
            fn new() -> Self {
                Self(PhantomData)
            }
        }
    };
}
pub(crate) use Rec;
