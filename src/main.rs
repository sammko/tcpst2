use std::net::Ipv4Addr;
use std::ops::Add;
use std::thread;

use anyhow::Result;
use crossbeam_channel::unbounded;
use log::info;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;

use tcpst2::cb::{Connected, CrossBeamRoleChannel, Data, Open, TcbCreated};
use tcpst2::smol_channel::{Ack, SmolChannel, SynAck};
use tcpst2::smol_lower::SmolLower;
use tcpst2::st::{Action, SessionTypedChannel};
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

    let st_system_server = ServerSystemSessionType::new();
    let st_sustem_user = ServerUserSessionType::new();

    thread::scope(|scope| {
        let thread_a = scope.spawn(|| {
            // Thread A simulates the kind of calls the userspace would send to the TCP system.
            // These are not actually implemented but it demonstrates the user of another
            // session typed channel on a different medium.
            // This also allows us to demonstrate the TCP system communicating with two sepparate participants.

            let cont = user_system_channel.select_one(st_sustem_user, Open {});
            let (_, cont) = user_system_channel.offer_one(cont);
            let (_, cont) = user_system_channel.offer_one(cont);

            let mut reccont = cont;
            loop {
                let cont = reccont.inner();
                let (rx, cont) = user_system_channel.offer_one(cont);

                let mut response = rx.data.clone();
                let str = String::from_utf8(rx.data).unwrap();
                println!("User received data: {:?}", str);

                let len = response.len();
                if len > 0 {
                    response[..len - 1].reverse();
                }

                reccont = user_system_channel.select_one(cont, Data { data: response });
            }

            // let cont = user_system_channel.select_one(cont, Close {});
            // let (_, cont) = user_system_channel.offer_one(cont);
            // user_system_channel.close(cont);
        });
        let thread_b = scope.spawn(|| {
            let smol_lower = SmolLower::new().unwrap();

            let mut net_channel = SmolChannel::<RoleServerSystem, RoleClientSystem>::new(
                smol_lower,
                smoltcp::wire::Ipv4Address::new(192, 168, 22, 100),
            );

            let mut seq = 123;

            // Thread B shows the communication from the point of the TCP system.
            // TCP system communicates with both the remote client and the local userspace.
            // The example only demonstrates establishing a handshake and then sending the closing packet.

            // Recieve the OPEN call from the user
            let (_, cont) = system_user_channel.offer_one(st_system_server);
            // Notify the user that the we are ready to accept an incoming connection
            let cont = system_user_channel.select_one(cont, TcbCreated {});

            // Recieve a SYN packet indicating the beginning of the opening handshake.
            let (syn_message, cont) = net_channel.offer_one(cont);

            // Construct a SYN-ACK packet and cast it to the appropriate message type.
            let packet = TcpPacket::new(&syn_message.packet).unwrap();
            let mut vec: Vec<u8> = vec![0; syn_message.packet.len()];
            let mut new_packet = MutableTcpPacket::new(&mut vec).unwrap();
            new_packet.set_flags(TcpFlags::ACK | TcpFlags::SYN);
            new_packet.set_sequence(seq);
            seq += 1;
            new_packet.set_acknowledgement(packet.get_sequence().add(1));
            new_packet.set_source(packet.get_destination());
            new_packet.set_destination(packet.get_source());
            new_packet.set_window(packet.get_window());
            new_packet.set_data_offset(packet.get_data_offset());
            let checksum = ipv4_checksum(&new_packet.to_immutable(), &local_addr, &remote_addr);
            new_packet.set_checksum(checksum);
            let new_packet_slice = new_packet.packet();

            // Send the message along the channel, following our session type.
            let cont = net_channel.select_one(
                cont,
                SynAck {
                    packet: new_packet_slice.to_vec(),
                },
            );

            // Recieve a message of type ACK.
            let (ack_message, cont) = net_channel.offer_one(cont);
            let packet = TcpPacket::new(&ack_message.packet).unwrap();
            // TODO validate packet

            // Notify the user that the connection was established.
            let mut reccont = system_user_channel.select_one(cont, Connected {});
            loop {
                let cont = reccont.inner();
                info!("next loop");

                // recv empty ack from peer
                let (_, cont) = net_channel.offer_one(cont);
                // TODO validate packet

                // Recieve data from peer
                let (data, cont) = net_channel.offer_one(cont);
                let packet = TcpPacket::new(&data.packet).unwrap();
                // TODO validate packet
                let cont = system_user_channel.select_one(
                    cont,
                    Data {
                        data: packet.payload().to_vec(),
                    },
                );

                let (data, cont) = system_user_channel.offer_one(cont);

                let mut vec: Vec<u8> = vec![0; 20 + data.data.len()];
                let mut new_packet = MutableTcpPacket::new(&mut vec).unwrap();
                new_packet.set_flags(TcpFlags::ACK | TcpFlags::PSH);
                new_packet.set_sequence(seq);
                println!("seq: {}", seq);
                new_packet
                    .set_acknowledgement(packet.get_sequence().add(packet.payload().len() as u32));
                new_packet.set_source(packet.get_destination());
                new_packet.set_destination(packet.get_source());
                new_packet.set_window(1024);
                new_packet.set_data_offset(5);
                new_packet.set_payload(&data.data);
                let checksum = ipv4_checksum(&new_packet.to_immutable(), &local_addr, &remote_addr);
                new_packet.set_checksum(checksum);
                let new_packet_slice = new_packet.packet();
                seq += data.data.len() as u32;

                reccont = net_channel.select_one(
                    cont,
                    Ack {
                        packet: new_packet_slice.to_vec(),
                    },
                );
            }
        });
        thread_a.join().unwrap();
        thread_b.join().unwrap();
    });

    Ok(())
}
