use std::net::Ipv4Addr;
use std::thread;

use anyhow::Result;
use crossbeam_channel::unbounded;
use log::{info, warn};

use smoltcp::time::Duration;
use tcpst2::cb::{
    Close, Connected, CrossBeamRoleChannel, Data, NetRepresentation, Open, TcbCreated,
};
use tcpst2::smol_channel::SmolChannel;
use tcpst2::smol_lower::SmolLower;
use tcpst2::st::{nested_offer_two, Action, Branch, Choice, Nested, Timeout};
use tcpst2::tcp::{LocalAddr, Reaction, ReactionInner, TcpClosed};
use tcpst2::{
    RoleClientSystem, RoleServerSystem, RoleServerUser, ServerSystemSessionType,
    ServerUserSessionType,
};

/// tcpst2 server
#[derive(argh::FromArgs, Debug)]
struct CmdlineArgs {
    #[argh(positional)]
    local_addr: Ipv4Addr,
}

macro_rules! not_in_st {
    () => {
        panic!("not represented in session type")
    };
    ($($arg:tt)*) => {
        panic!("not represented in session type: {}", format!($($arg)*))
    }
}

fn main() -> Result<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = argh::from_env::<CmdlineArgs>();

    // Create the underlying communication channel and the session typed CrossbeamChannel
    let (cbtx1, cbrx1) = unbounded();
    let (cbtx2, cbrx2) = unbounded();
    let mut system_user_channel =
        CrossBeamRoleChannel::<RoleServerSystem, RoleServerUser>::new(cbtx2, cbrx1);
    let mut user_system_channel =
        CrossBeamRoleChannel::<RoleServerUser, RoleServerSystem>::new(cbtx1, cbrx2);

    thread::scope(|scope| {
        let thread_a = scope.spawn(|| {
            // Thread A simulates the kind of calls the userspace would send to the TCP system.
            // These are not actually implemented but it demonstrates the user of another
            // session typed channel on a different medium.
            // This also allows us to demonstrate the TCP system communicating with two sepparate participants.
            let st = ServerUserSessionType::new();

            let st = user_system_channel.select_one(st, Open(()));
            let (_tcb_created, st) = user_system_channel.offer_one(st);
            let mut recursive = match user_system_channel.offer_two(st, |net| match net {
                NetRepresentation::Connected(_) => Choice::Left,
                NetRepresentation::Close(_) => Choice::Right,
                _ => unreachable!(),
            }) {
                Branch::Left((_connected, st)) => st,
                Branch::Right((_close, end)) => {
                    user_system_channel.close(end);
                    return;
                }
            };

            'top: loop {
                let st = recursive.inner();

                match user_system_channel.offer_two(st, |net| match net {
                    NetRepresentation::Data(_) => Choice::Left,
                    NetRepresentation::Close(_) => Choice::Right,
                    _ => unreachable!(),
                }) {
                    Branch::Left((data, st)) => {
                        let mut message = data.0;

                        println!(
                            "User received data: {:?}",
                            std::str::from_utf8(&message).unwrap_or("<invalid utf8>")
                        );

                        if message.len() <= 1 {
                            let st = user_system_channel.select_right(st, Close(()));
                            user_system_channel.close(st);
                            break 'top;
                        }

                        message
                            .split_mut(|b| *b == 0x0a)
                            .for_each(|line| line.reverse());
                        recursive = user_system_channel.select_left(st, Data(message));
                        continue;
                    }
                    Branch::Right((_close, recursive)) => {
                        let st = recursive.inner();
                        let st = user_system_channel.select_right(st, Close(()));
                        user_system_channel.close(st);
                        break 'top;
                    }
                }
            }
        });
        let thread_b = scope.spawn(|| {
            // Thread B shows the communication from the point of the TCP system.
            // TCP system communicates with both the remote client and the local userspace.

            let smol_lower = SmolLower::new(args.local_addr.into()).unwrap();
            let checksum_caps = smol_lower.checksum_caps();
            let mut net_channel =
                SmolChannel::<RoleServerSystem, RoleClientSystem>::new(smol_lower);
            let st = ServerSystemSessionType::new();
            let tcp = TcpClosed::new();

            // await Open call from user
            let (_open, st) = system_user_channel.offer_one(st);
            let tcp = tcp.open(LocalAddr {
                addr: args.local_addr.into(),
                port: 555,
                checksum_caps,
            } /* TODO take this from user */);

            let st = system_user_channel.select_one(st, TcbCreated(()));

            let (addr, syn, st) = net_channel.offer_one_with_addr(st, &tcp);

            let (mut tcp, synack) = tcp.recv_syn(addr, &syn);
            let mut syn_rcvd = net_channel.select_one(st, addr, synack);

            let (mut tcp, st) = loop {
                let st = syn_rcvd.inner();
                let tcp_for_picker = tcp.for_picker();
                match net_channel.offer_two_filtered(
                    st,
                    |packet| {
                        if let Some(packet) = packet {
                            match tcp_for_picker.acceptable(&packet) {
                                ReactionInner::Acceptable(_, _) => Branch::Left(packet.into()),
                                _ => Branch::Right(packet.into()),
                            }
                        } else {
                            unreachable!()
                        }
                    },
                    &tcp,
                    None,
                ) {
                    Branch::Left((acceptable, st)) => {
                        let tcp = tcp
                            .recv_ack(&acceptable)
                            .empty_acceptable()
                            .expect("First ACK must be empty");
                        break (tcp, st);
                    }
                    Branch::Right((unacceptable, st)) => {
                        let remote_addr = tcp.remote_addr();
                        match tcp.recv_ack(&unacceptable) {
                            Reaction::Acceptable(_, _, _) => unreachable!(),
                            Reaction::NotAcceptable(tcp2, Some(resp)) => {
                                let st = net_channel.select_left(st, tcp2.remote_addr(), resp);
                                syn_rcvd = st;
                                tcp = tcp2;
                                continue;
                            }
                            Reaction::NotAcceptable(_, None) => unreachable!(),
                            Reaction::Reset(Some(rst)) => {
                                let st = net_channel.select_right(st, remote_addr, rst);
                                let end = system_user_channel.select_one(st, Close(()));
                                net_channel.close(end);
                                system_user_channel.close(end);
                                return;
                            }
                            Reaction::Reset(None) => unreachable!(),
                        };
                    }
                }
            };

            let mut recursive = system_user_channel.select_one(st, Connected(()));
            info!("established");

            let mut timeout = None;
            'top: loop {
                let st = recursive.inner();

                let tcp_for_picker = tcp.for_picker();
                let timeout2 = timeout;
                timeout = None; // reset timeout for next iteration
                match net_channel.offer_two_filtered(
                    st,
                    move |packet| {
                        if let Some(packet) = packet {
                            if packet.fin() {
                                // TODO unacceptable FINs are not handled properly
                                Branch::Right(Nested::Right(Nested::Left(packet.into())))
                            } else {
                                match tcp_for_picker.acceptable(&packet) {
                                    ReactionInner::Acceptable(_, Some(_)) => {
                                        Branch::Left(packet.into())
                                    }
                                    ReactionInner::Acceptable(_, None) => {
                                        Branch::Right(Nested::Left(packet.into()))
                                    }
                                    _ => Branch::Right(Nested::Right(Nested::Right(Nested::Left(
                                        packet.into(),
                                    )))),
                                }
                            }
                        } else {
                            Branch::Right(Nested::Right(Nested::Right(Nested::Right(Timeout))))
                        }
                    },
                    &tcp,
                    timeout2,
                ) {
                    Branch::Left((acceptable_with_data, st)) => {
                        let resp;
                        let data: &[u8];
                        (tcp, resp, data) = match tcp.recv(&acceptable_with_data) {
                            Reaction::Acceptable(tcp, Some(resp), Some(data)) => (tcp, resp, data),
                            Reaction::Acceptable(_, Some(_), None) => unreachable!(),
                            Reaction::Acceptable(_, None, _) => unreachable!(),
                            Reaction::NotAcceptable(_, _) => unreachable!(),
                            Reaction::Reset(_) => unreachable!(),
                        };
                        let st = net_channel.select_one(st, tcp.remote_addr(), resp);

                        info!("Got {:?} bytes", data.len());

                        let st = system_user_channel.select_one(st, Data(data.to_owned()));

                        match system_user_channel.offer_two(st, |net| match net {
                            NetRepresentation::Data(_) => Choice::Left,
                            NetRepresentation::Close(_) => Choice::Right,
                            _ => unreachable!(),
                        }) {
                            Branch::Left((data, st)) => {
                                let tx = tcp.send(&data.0);
                                let st = net_channel.select_one(st, tcp.remote_addr(), tx);
                                recursive = st;
                                timeout = Some(Duration::from_secs(1));
                            }
                            Branch::Right((_close, st)) => {
                                let (tcp, fin) = tcp.close();
                                let st = net_channel.select_one(st, tcp.remote_addr(), fin);

                                let (rx, mut recursive) = net_channel.offer_one_filtered(st, &tcp);
                                let mut tcp = tcp
                                    .recv(&rx)
                                    .empty_acceptable()
                                    .expect("FIN of ACK must be empty");

                                loop {
                                    let st = recursive.inner();
                                    match net_channel.offer_two_filtered(
                                        st,
                                        |packet| {
                                            let packet = packet.unwrap();
                                            if packet.fin() {
                                                Branch::Right(packet.into())
                                            } else {
                                                Branch::Left(packet.into())
                                            }
                                        },
                                        &tcp,
                                        None,
                                    ) {
                                        Branch::Left((ack, st)) => {
                                            // We have received data from the Client, but we
                                            // will just throw it away, since our user has
                                            // closed.
                                            let ack = tcp.recv_ack(&ack);
                                            recursive =
                                                net_channel.select_one(st, tcp.remote_addr(), ack);
                                            continue;
                                        }
                                        Branch::Right((fin, st)) => {
                                            let remote_addr = tcp.remote_addr();
                                            let ack = tcp.recv_fin(&fin);
                                            let end = net_channel.select_one(st, remote_addr, ack);
                                            net_channel.close(end);
                                            system_user_channel.close(end);
                                            break 'top;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Branch::Right((nested, st)) => match nested_offer_two(st, nested) {
                        Branch::Left((acceptable_empty, st)) => {
                            tcp = tcp.recv(&acceptable_empty).empty_acceptable().unwrap();
                            recursive = st;
                        }
                        Branch::Right((nested, st)) => match nested_offer_two(st, nested) {
                            Branch::Left((fin, st)) => {
                                let (mut tcp, ack) = match tcp.recv_fin(&fin) {
                                    Reaction::Acceptable(_, _, Some(_)) => todo!("payload in FIN"),
                                    Reaction::Acceptable(tcp, Some(ack), None) => (tcp, ack),
                                    Reaction::Acceptable(_, None, _) => unreachable!(),
                                    Reaction::NotAcceptable(_, _) => not_in_st!("bad FIN"),
                                    Reaction::Reset(_) => not_in_st!("reset from bad FIN"),
                                };
                                let st = net_channel.select_one(st, tcp.remote_addr(), ack);
                                let mut recursive = system_user_channel.select_one(st, Close(()));
                                loop {
                                    let st = recursive.inner();
                                    match system_user_channel.offer_two(st, |net| match net {
                                        NetRepresentation::Data(_) => Choice::Left,
                                        NetRepresentation::Close(_) => Choice::Right,
                                        _ => unreachable!(),
                                    }) {
                                        Branch::Left((data, st)) => {
                                            let tx = tcp.send(&data.0);
                                            let st =
                                                net_channel.select_one(st, tcp.remote_addr(), tx);
                                            let (ack, st) =
                                                net_channel.offer_one_filtered(st, &tcp);
                                            tcp.recv_ack(&ack);
                                            recursive = st;
                                        }
                                        Branch::Right((_close, st)) => {
                                            let (tcp, fin) = tcp.close();
                                            let st =
                                                net_channel.select_one(st, tcp.remote_addr(), fin);
                                            let (ack, end) =
                                                net_channel.offer_one_filtered(st, &tcp);
                                            tcp.recv_ack(&ack);
                                            net_channel.close(end);
                                            system_user_channel.close(end);
                                            break 'top;
                                        }
                                    }
                                }
                            }
                            Branch::Right((nested, st)) => match nested_offer_two(st, nested) {
                                Branch::Left((not_acceptable, st)) => {
                                    warn!("Not acceptable");
                                    let challenge;
                                    (tcp, challenge) = match tcp.recv(&not_acceptable) {
                                        Reaction::Acceptable(_, _, _) => {
                                            unreachable!()
                                        }
                                        Reaction::NotAcceptable(tcp, Some(challenge)) => {
                                            (tcp, challenge)
                                        }
                                        Reaction::NotAcceptable(_, None) => not_in_st!(),
                                        Reaction::Reset(_) => not_in_st!(),
                                    };
                                    recursive =
                                        net_channel.select_one(st, tcp.remote_addr(), challenge);
                                }
                                Branch::Right((_, st)) => {
                                    let ack = tcp.retransmission().expect("Nothing to retransmit");
                                    recursive = net_channel.select_one(st, tcp.remote_addr(), ack);
                                    timeout = Some(Duration::from_secs(1));
                                }
                            },
                        },
                    },
                }
            }
        });
        thread_a.join().unwrap();
        thread_b.join().unwrap();
    });

    Ok(())
}
