// RouterLab: Orchestration Layer to Automate Experiments on Network Routers
// Copyright (C) 2022-2025 Tibor Schneider <sctibor@ethz.ch> and Roland Schmid <roschmi@ethz.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![feature(vec_into_raw_parts)]

use std::{
    io::{stdout, Write},
    net::Ipv4Addr,
    panic::catch_unwind,
    process::exit,
};

use clap::Parser;
use libc::timespec;

mod raw_socket;
use pnet_base::MacAddr;
use pnet_packet::{ethernet, ip::IpNextHeaderProtocols, ipv4, Packet};
use raw_socket::{create_socket, iface_disable_promisc_mode, iface_enable_promisc_mode, recv_pkt};

pub type RawPacket = Vec<u8>;

pub const PAYLOAD_SIZE: usize = 8;
pub const IPV4_HEADER_SIZE: usize = 20;
pub const ETH_HEADER_SIZE: usize = 14;
pub const PACKET_SIZE: usize = PAYLOAD_SIZE + IPV4_HEADER_SIZE + ETH_HEADER_SIZE;

/// Sniff on the interface and print all packets that were sent using the `prober`.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Interface name to delay packets on.
    iface: String,
    /// How many messages should be buffered before sending them to stdout.
    #[clap(long, short = 'b', default_value = "8")]
    buffer: usize,
}

fn main() {
    let args = Args::parse();
    let iface = args.iface;
    let iface_for_handler = iface.clone();

    // create the socket
    let sock = create_socket(&iface);

    // register ctrl-c handle
    ctrlc::set_handler(move || {
        iface_disable_promisc_mode(sock, &iface_for_handler);
        println!("good night!");
        exit(0);
    })
    .unwrap();

    // enable promisc mode
    iface_enable_promisc_mode(sock, &iface);

    // run the delayer, but catch any panic.
    let _ = catch_unwind(|| delayer(sock, args.buffer));

    // disable promisc mode
    iface_disable_promisc_mode(sock, &iface);
}

#[allow(clippy::print_with_newline)]
fn delayer(sock: i32, buffer_size: usize) -> ! {
    let mut initial_ts = None;
    let mut buffered: usize = 0;

    loop {
        if let Some((mac, src, dst, idx, ts)) = process_pkt(recv_pkt(sock)) {
            if initial_ts.is_none() {
                initial_ts = Some(ts);
            }
            // let delta = ts_sub(ts, unsafe { initial_ts.unwrap_unchecked() });
            print!("{}.{:09},{mac},{src},{dst},{idx}\n", ts.tv_sec, ts.tv_nsec);
            buffered += 1;
            if buffered >= buffer_size {
                let _ = stdout().flush();
                buffered = 0;
            }
        }
    }
}

pub fn process_pkt(
    data: (RawPacket, timespec),
) -> Option<(MacAddr, Ipv4Addr, Ipv4Addr, u64, timespec)> {
    let (pkt, recv_ts) = data;

    // check if the packet has length at least 18 bytes long
    if pkt.len() < PACKET_SIZE {
        return None;
    }

    // construct the packet
    let Some(eth) = ethernet::EthernetPacket::new(&pkt) else {
        return None;
    };

    // check the type
    if eth.get_ethertype() != ethernet::EtherTypes::Ipv4 {
        return None;
    }

    let Some(ip) = ipv4::Ipv4Packet::new(eth.payload()) else {
        return None;
    };

    // check the protocol is Test1
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Test1 {
        return None;
    }

    // get the idx
    let Ok(idx) = ip.payload().try_into().map(u64::from_be_bytes) else {
        eprintln!("Packet does not contain enough bytes for the index!");
        return None;
    };

    // get the content
    let mac = eth.get_source();
    let src = ip.get_source();
    let dst = ip.get_destination();
    Some((mac, src, dst, idx, recv_ts))
}

const NS_PER_SEC: i64 = 1_000_000_000;

#[inline(always)]
pub fn ts_sub(a: timespec, b: timespec) -> timespec {
    let mut tv = timespec {
        tv_sec: a.tv_sec - b.tv_sec,
        tv_nsec: a.tv_nsec - b.tv_nsec,
    };

    if tv.tv_sec > 0 && tv.tv_nsec < 0 {
        tv.tv_nsec += NS_PER_SEC;
        tv.tv_sec -= 1;
    } else if tv.tv_sec < 0 && tv.tv_nsec > 0 {
        tv.tv_nsec -= NS_PER_SEC;
        tv.tv_sec += 1;
    }

    tv
}
