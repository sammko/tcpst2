use std::net::Ipv4Addr;
use std::thread;

use anyhow::Result;
use crossbeam_channel::unbounded;
use log::info;

use tcpst2::cb::{Close, Connected, CrossBeamRoleChannel, Data, Open, TcbCreated};
use tcpst2::smol_channel::SmolChannel;
use tcpst2::smol_lower::SmolLower;
use tcpst2::st::{Action, Branch, Choice, SessionTypedChannel};
use tcpst2::tcp::{LocalAddr, TcpClosed};
use tcpst2::{
    RoleClientSystem, RoleServerSystem, RoleServerUser, ServerSystemSessionType,
    ServerUserSessionType,
};

fn main() -> Result<()> {
    pretty_env_logger::init();

    let remote_addr = Ipv4Addr::new(192, 168, 22, 100);
    let local_addr = Ipv4Addr::new(192, 168, 22, 1);

    // Create the underlying communication channel and the session typed CrossbeamChannel
    let (cbtx1, cbrx1) = unbounded();
    let (cbtx2, cbrx2) = unbounded();
    let mut system_user_channel =
        CrossBeamRoleChannel::<RoleServerSystem, RoleServerUser>::new(cbtx2, cbrx1);
    let mut user_system_channel =
        CrossBeamRoleChannel::<RoleServerUser, RoleServerSystem>::new(cbtx1, cbrx2);

    let st_sustem_user = ServerUserSessionType::new();

    thread::scope(|scope| {
        let thread_a = scope.spawn(|| {
            // Thread A simulates the kind of calls the userspace would send to the TCP system.
            // These are not actually implemented but it demonstrates the user of another
            // session typed channel on a different medium.
            // This also allows us to demonstrate the TCP system communicating with two sepparate participants.

            let cont =
                user_system_channel.select_one(st_sustem_user, Open { /* always passive */ });
            let (_, cont) = user_system_channel.offer_one(cont);
            let (_, cont) = user_system_channel.offer_one(cont);

            let mut reccont = cont;
            loop {
                let cont = reccont.inner();
                let (rx, cont) = user_system_channel.offer_one(cont);

                let mut response = rx.data.clone();
                let str = String::from_utf8(rx.data).unwrap();
                println!("User received data: {:?}", str);

                if response.len() > 1 {
                    let len = response.len();
                    response[..len - 1].reverse();
                    reccont = user_system_channel.select_left(cont, Data { data: response })
                } else {
                    let cont = user_system_channel.select_right(cont, Close {});
                    user_system_channel.close(cont);
                    break;
                }
            }

            // let cont = user_system_channel.select_one(cont, Close {});
            // let (_, cont) = user_system_channel.offer_one(cont);
            // user_system_channel.close(cont);
        });
        let thread_b = scope.spawn(|| {
            // Thread B shows the communication from the point of the TCP system.
            // TCP system communicates with both the remote client and the local userspace.

            let smol_lower = SmolLower::new().unwrap();
            let checksum_caps = smol_lower.checksum_caps();
            let mut net_channel = SmolChannel::<RoleServerSystem, RoleClientSystem>::new(
                smol_lower,
                smoltcp::wire::Ipv4Address::new(192, 168, 22, 100),
            );
            let st = ServerSystemSessionType::new();
            let tcp = TcpClosed::new();

            // await Open call from user
            let (_open, st) = system_user_channel.offer_one(st);
            let tcp = tcp.open(LocalAddr {
                addr: local_addr,
                port: 555,
                checksum_caps,
            } /* TODO take this from user */);

            let st = system_user_channel.select_one(st, TcbCreated {});

            let (syn, st) = net_channel.offer_one(st);
            let (tcp, synack) = tcp.recv_syn(remote_addr, &syn);
            let st = net_channel.select_one(st, synack);

            let (ack, st) = net_channel.offer_one(st);
            let mut tcp = tcp.recv_ack(&ack);

            let st = system_user_channel.select_one(st, Connected {});
            info!("established");

            let mut recursive = st;
            loop {
                let st = recursive.inner();

                let (rx, st) = net_channel.offer_one(st);
                let (resp, data) = tcp.recv(&rx);
                let st = net_channel.select_one(st, resp);

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
                        let (ack, st) = net_channel.offer_one(st);
                        tcp.recv(&ack);
                        recursive = st;
                        continue;
                    }
                    Branch::Right((_close, end)) => {
                        // TODO close sequence
                        system_user_channel.close(end);
                        // I think the `End` concept doesn't work since we want
                        // to be able to close both channels and only have one
                        // End?
                        // net_channel.close(end)
                        break;
                    }
                }
            }
        });
        thread_a.join().unwrap();
        thread_b.join().unwrap();
    });

    Ok(())
}
