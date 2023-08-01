use std::net::Ipv4Addr;
use std::thread;

use anyhow::Result;
use crossbeam_channel::unbounded;
use log::info;

use tcpst2::cb::{Close, Connected, CrossBeamRoleChannel, Data, Open, TcbCreated};
use tcpst2::smol_channel::SmolChannel;
use tcpst2::smol_lower::SmolLower;
use tcpst2::st::{Action, Branch, Choice};
use tcpst2::tcp::{LocalAddr, TcpClosed};
use tcpst2::{
    RoleClientSystem, RoleServerSystem, RoleServerUser, ServerSystemSessionType,
    ServerUserSessionType,
};

/// tcpst2 server
#[derive(argh::FromArgs, Debug)]
struct CmdlineArgs {
    #[argh(positional)]
    local_addr: Ipv4Addr,

    #[argh(positional)]
    remote_addr: Ipv4Addr,
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
                        let st = user_system_channel
                            .select_left(
                                st,
                                Data {
                                    data: b"closing".to_vec(),
                                },
                            )
                            .inner();
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
            let mut net_channel = SmolChannel::<RoleServerSystem, RoleClientSystem>::new(
                smol_lower,
                args.remote_addr.into(),
            );
            let st = ServerSystemSessionType::new();
            let tcp = TcpClosed::new();

            // await Open call from user
            let (_open, st) = system_user_channel.offer_one(st);
            let tcp = tcp.open(LocalAddr {
                addr: args.local_addr,
                port: 555,
                checksum_caps,
            } /* TODO take this from user */);

            let st = system_user_channel.select_one(st, TcbCreated {});

            let (syn, st) = net_channel.offer_one_filtered(st, &tcp);

            let (tcp, synack) = tcp.recv_syn(args.remote_addr, &syn);
            let st = net_channel.select_one(st, synack);

            let (ack, st) = net_channel.offer_one_filtered(st, &tcp);
            let mut tcp = tcp.recv_ack(&ack);

            let st = system_user_channel.select_one(st, Connected {});
            info!("established");

            let mut recursive = st;
            'top: loop {
                let st = recursive.inner();

                match net_channel.offer_two_filtered(
                    st,
                    |packet| {
                        if packet.fin() {
                            Choice::Right
                        } else {
                            Choice::Left
                        }
                    },
                    &tcp,
                ) {
                    Branch::Left((rx, st)) => {
                        let (resp, data) = tcp.recv(&rx);
                        let st = net_channel.select_one(st, resp.expect("not represented by ST"));

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
                                let st = net_channel.select_one(st, tx);
                                let (ack, st) = net_channel.offer_one_filtered(st, &tcp);
                                tcp.recv(&ack);
                                recursive = st;
                                continue;
                            }
                            Branch::Right((_close, st)) => {
                                let (tcp, fin) = tcp.close();
                                let st = net_channel.select_one(st, fin);

                                let (rx, mut recursive) = net_channel.offer_one_filtered(st, &tcp);
                                let mut tcp = tcp.recv(&rx);

                                loop {
                                    let st = recursive.inner();
                                    match net_channel.offer_two_filtered(
                                        st,
                                        |packet| {
                                            if packet.fin() {
                                                Choice::Right
                                            } else {
                                                Choice::Left
                                            }
                                        },
                                        &tcp,
                                    ) {
                                        Branch::Left((ack, st)) => {
                                            // We have received data from the Client, but we
                                            // will just throw it away, since our user has
                                            // closed.
                                            let ack = tcp.recv_ack(&ack);
                                            recursive = net_channel.select_one(st, ack);
                                            continue;
                                        }
                                        Branch::Right((fin, st)) => {
                                            let ack = tcp.recv_fin(&fin);
                                            let st = net_channel.select_one(st, ack);
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
                    Branch::Right((fin, st)) => {
                        let (mut tcp, ack) = tcp.recv_fin(&fin);
                        let st = net_channel.select_one(st, ack);
                        let mut recursive = system_user_channel.select_one(st, Close {});
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
                                    let st = net_channel.select_one(st, tx);
                                    let (ack, st) = net_channel.offer_one_filtered(st, &tcp);
                                    tcp.recv_ack(&ack);
                                    recursive = st;
                                    continue;
                                }
                                Branch::Right((_close, st)) => {
                                    let (tcp, fin) = tcp.close();
                                    let st = net_channel.select_one(st, fin);
                                    let (ack, st) = net_channel.offer_one_filtered(st, &tcp);
                                    tcp.recv_ack(&ack);
                                    net_channel.close(st);
                                    break 'top;
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
