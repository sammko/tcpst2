use std::net::Ipv4Addr;
use std::thread;

use anyhow::Result;
use crossbeam_channel::unbounded;
use log::{info, warn};

use smoltcp::wire::TcpPacket;
use tcpst2::cb::{Close, Connected, CrossBeamRoleChannel, Data, Open, TcbCreated};
use tcpst2::smol_channel::SmolChannel;
use tcpst2::smol_lower::SmolLower;
use tcpst2::st::{nested_offer_two, Action, Branch, Choice, Nested};
use tcpst2::tcp::{LocalAddr, Reaction, TcpClosed};
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

fn main() -> Result<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Trace)
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

            let st = user_system_channel.select_one(st, Open { /* always passive */ });
            let (_tcb_created, st) = user_system_channel.offer_one(st);
            let (_connected, st) = user_system_channel.offer_one(st);

            let mut recursive = st;
            'top: loop {
                let st = recursive.inner();

                match user_system_channel.offer_two(st, |payload| {
                    // TODO improve this signalling
                    if payload.len() > 0 {
                        Choice::Left
                    } else {
                        Choice::Right
                    }
                }) {
                    Branch::Left((data, st)) => {
                        let mut message = data.data;

                        println!(
                            "User received data: {:?}",
                            std::str::from_utf8(&message).unwrap_or("<invalid utf8>")
                        );

                        if message.len() > 1 {
                            let len = message.len();
                            message[..len - 1].reverse();
                            recursive = user_system_channel.select_left(st, Data { data: message });
                            continue;
                        } else {
                            let st = user_system_channel.select_right(st, Close {});
                            user_system_channel.close(st);
                            break 'top;
                        }
                    }
                    Branch::Right((_close, recursive)) => {
                        let st = recursive.inner();
                        let st = user_system_channel.select_right(st, Close {});
                        user_system_channel.close(st);
                        break 'top;
                    }
                }
            }

            // let cont = user_system_channel.select_one(cont, Close {});
            // let (_, cont) = user_system_channel.offer_one(cont);
            // user_system_channel.close(cont);
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

            let st = system_user_channel.select_one(st, TcbCreated {});

            let (addr, syn, st) = net_channel.offer_one_with_addr(st, &tcp);

            let (tcp, synack) = tcp.recv_syn(addr, &syn);
            let st = net_channel.select_one(st, addr, synack);

            let (ack, st) = net_channel.offer_one_filtered(st, &tcp);
            let mut tcp = tcp.recv_ack(&ack);

            let st = system_user_channel.select_one(st, Connected {});
            info!("established");

            let mut recursive = st;
            'top: loop {
                let st = recursive.inner();

                let tcp_for_picker = tcp.for_picker();
                match net_channel.offer_two_filtered(
                    st,
                    move |packet| {
                        if packet.fin() {
                            Branch::Right(Nested::Right(Nested::Left(packet.into())))
                        } else {
                            match tcp_for_picker.acceptable(&packet) {
                                true => match TcpPacket::new_unchecked(&packet).payload().len() {
                                    0 => Branch::Right(Nested::Left(packet.into())),
                                    _ => Branch::Left(packet.into()),
                                },
                                false => Branch::Right(Nested::Right(Nested::Right(packet.into()))),
                            }
                        }
                    },
                    &tcp,
                ) {
                    Branch::Left((acceptable_with_data, st)) => {
                        let (resp, data): (_, &[u8]) = match tcp.recv(&acceptable_with_data) {
                            Reaction::Acceptable(Some(resp), Some(data)) => (resp, data),
                            Reaction::Acceptable(Some(resp), None) => (resp, &[]),
                            Reaction::Acceptable(None, _) => unreachable!(),
                            Reaction::NotAcceptable(_) => unreachable!(),
                            Reaction::Reset(_) => unreachable!(),
                        };
                        let st = net_channel.select_one(st, tcp.remote_addr(), resp);

                        info!("Got {:?} bytes", data.len());

                        let st = system_user_channel.select_one(
                            st,
                            Data {
                                data: data.to_owned(),
                            },
                        );

                        match system_user_channel.offer_two(st, |payload| {
                            // TODO improve this signalling
                            if payload.len() > 0 {
                                Choice::Left
                            } else {
                                Choice::Right
                            }
                        }) {
                            Branch::Left((data, st)) => {
                                let tx = tcp.send(&data.data);
                                let st = net_channel.select_one(st, tcp.remote_addr(), tx);
                                recursive = st;
                                continue 'top;
                            }
                            Branch::Right((_close, st)) => {
                                let (tcp, fin) = tcp.close();
                                let st = net_channel.select_one(st, tcp.remote_addr(), fin);

                                let (rx, mut recursive) = net_channel.offer_one_filtered(st, &tcp);
                                let mut tcp = tcp.recv(&rx);

                                loop {
                                    let st = recursive.inner();
                                    match net_channel.offer_two_filtered(
                                        st,
                                        |packet| {
                                            if packet.fin() {
                                                Branch::Right(packet.into())
                                            } else {
                                                Branch::Left(packet.into())
                                            }
                                        },
                                        &tcp,
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
                                            let st = net_channel.select_one(st, remote_addr, ack);
                                            net_channel.close(st);
                                            // I think the `End` concept doesn't work since we want
                                            // to be able to close both channels and only have one
                                            // End? Maybe we can make it Clone?
                                            break 'top;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Branch::Right((nested, st)) => {
                        match nested_offer_two(st, nested) {
                            Branch::Left((acceptable_empty, st)) => {
                                match tcp.recv(&acceptable_empty) {
                                    Reaction::Acceptable(None, None) => {
                                        recursive = st;
                                        continue 'top;
                                    }
                                    Reaction::Acceptable(_, _) => unreachable!(),
                                    Reaction::NotAcceptable(_) => unreachable!(),
                                    Reaction::Reset(_) => unreachable!(),
                                }
                            }
                            Branch::Right((nested, st)) => {
                                match nested_offer_two(st, nested) {
                                    Branch::Left((fin, st)) => {
                                        let (mut tcp, ack) = tcp.recv_fin(&fin);
                                        let st = net_channel.select_one(st, tcp.remote_addr(), ack);
                                        let mut recursive =
                                            system_user_channel.select_one(st, Close {});
                                        loop {
                                            let st = recursive.inner();
                                            match system_user_channel.offer_two(st, |payload| {
                                                // TODO improve this signalling
                                                if payload.len() > 0 {
                                                    Choice::Left
                                                } else {
                                                    Choice::Right
                                                }
                                            }) {
                                                Branch::Left((data, st)) => {
                                                    let tx = tcp.send(&data.data);
                                                    let st = net_channel.select_one(
                                                        st,
                                                        tcp.remote_addr(),
                                                        tx,
                                                    );
                                                    let (ack, st) =
                                                        net_channel.offer_one_filtered(st, &tcp);
                                                    tcp.recv_ack(&ack);
                                                    recursive = st;
                                                    continue;
                                                }
                                                Branch::Right((_close, st)) => {
                                                    let (tcp, fin) = tcp.close();
                                                    let st = net_channel.select_one(
                                                        st,
                                                        tcp.remote_addr(),
                                                        fin,
                                                    );
                                                    let (ack, st) =
                                                        net_channel.offer_one_filtered(st, &tcp);
                                                    tcp.recv_ack(&ack);
                                                    net_channel.close(st);
                                                    break 'top;
                                                }
                                            }
                                        }
                                    }
                                    Branch::Right((not_acceptable, st)) => {
                                        warn!("Not acceptable");
                                        let challenge = match tcp.recv(&not_acceptable) {
                                            Reaction::Acceptable(_, _) => unreachable!(),
                                            Reaction::NotAcceptable(Some(challenge)) => challenge,
                                            Reaction::NotAcceptable(None) => todo!(),
                                            Reaction::Reset(_) => todo!(),
                                        };
                                        recursive = net_channel.select_one(
                                            st,
                                            tcp.remote_addr(),
                                            challenge,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        thread_a.join().unwrap();
        thread_b.join().unwrap();
    });

    Ok(())
}
