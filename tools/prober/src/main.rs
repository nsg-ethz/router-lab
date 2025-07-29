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
    fs::read_to_string,
    io::{stdout, Write},
    net::Ipv4Addr,
    panic::catch_unwind,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;

mod raw_socket;
use pnet_base::MacAddr;
use pnet_packet::{ethernet, ip::IpNextHeaderProtocols, ipv4};
use raw_socket::{create_socket, send_pkt};
use serde::Deserialize;

pub const PAYLOAD_SIZE: usize = 8;
pub const IPV4_HEADER_SIZE: usize = 20;
pub const ETH_HEADER_SIZE: usize = 14;
pub const PACKET_SIZE: usize = PAYLOAD_SIZE + IPV4_HEADER_SIZE + ETH_HEADER_SIZE;
pub type RawPacket = [u8; PACKET_SIZE];
const SLEEP_ACCURACY: Duration = Duration::new(0, 125_000);

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file to read
    config_file: String,
    /// Overwrite the frequency.
    #[clap(long, short = 'f')]
    freq: Option<u64>,
    /// Overwrite the interface
    #[clap(long, short = 'i')]
    iface: Option<String>,
    /// How many messages should be buffered before sending them to stdout.
    #[clap(long, short = 'b', default_value = "8")]
    buffer: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Interface name to delay packets on.
    iface: String,
    /// number of microseconds between two packets of each flow
    freq: u64,
    /// The flows to generate traffic for
    flows: Vec<TrafficFlow>,
}

/// Describing a single traffic flow to monitor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct TrafficFlow {
    /// MAC Address of a port of the source router
    pub src_mac: [u8; 6],
    /// Source IP address for the ping packet
    pub src_ip: Ipv4Addr,
    /// Destination IP Address for the ping packet
    pub dst_ip: Ipv4Addr,
}

fn main() {
    let args = Args::parse();
    let mut config: Config =
        toml::from_str(&read_to_string(args.config_file).expect("Config file was not found!"))
            .expect("Cannot parse the config file");
    if let Some(freq) = args.freq {
        config.freq = freq
    }
    if let Some(iface) = args.iface {
        config.iface = iface
    }

    // create the socket
    let sock = create_socket(&config.iface);

    // handle process signals to disable promisc mode again.
    let kill = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, kill.clone()).unwrap();
    signal_hook::flag::register(signal_hook::consts::SIGTERM, kill.clone()).unwrap();
    signal_hook::flag::register(signal_hook::consts::SIGQUIT, kill.clone()).unwrap();

    // run the delayer, but catch any panic.
    let _ = catch_unwind(|| prober(sock, kill, config, args.buffer));

    // disable promisc mode
    println!("good night!")
}

fn generate_packet(flow: &TrafficFlow) -> (RawPacket, String) {
    let mut packet = [0; PACKET_SIZE];

    // generate the IP packet
    let mut ipv4 = ipv4::MutableIpv4Packet::new(&mut packet[ETH_HEADER_SIZE..]).unwrap();
    ipv4.set_version(4);
    ipv4.set_header_length((IPV4_HEADER_SIZE / 4) as u8);
    ipv4.set_total_length((IPV4_HEADER_SIZE + PAYLOAD_SIZE) as u16);
    ipv4.set_ttl(25);
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Test1);
    ipv4.set_source(flow.src_ip);
    ipv4.set_destination(flow.dst_ip);
    ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));

    // generate the ethernet packet
    let mut eth = ethernet::MutableEthernetPacket::new(&mut packet[..]).unwrap();
    eth.set_destination(flow.src_mac.into());
    eth.set_source(MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00));
    eth.set_ethertype(ethernet::EtherTypes::Ipv4);

    // generate the string
    let debug_str = format!(",{},{},", flow.src_ip, flow.dst_ip);

    (packet, debug_str)
}

fn prober(sock: i32, kill: Arc<AtomicBool>, config: Config, buffer_size: usize) {
    // prepare all packets
    let mut packets: Vec<(RawPacket, String)> = config.flows.iter().map(generate_packet).collect();

    let mut data_idx: u64 = 0;
    let mut data_bytes: [u8; 8] = [0; 8];
    let mut packet_idx: usize = 0;
    let num_packets = packets.len();

    let freq_ns = (config.freq * 1_000) / num_packets as u64;
    let sleep_dur = Duration::from_nanos(freq_ns);

    let mut current_time = Instant::now();

    let mut buffered = 0;

    while !kill.load(Ordering::Relaxed) {
        // register a new spin sleeper
        let sleeper = SpinSleeper::new(current_time);

        // get the next packet
        let (pkt, text) = &mut packets[packet_idx];
        pkt[ETH_HEADER_SIZE + IPV4_HEADER_SIZE..].copy_from_slice(&data_bytes);

        // send the packet
        send_pkt(sock, pkt);

        // create the logging output
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Default::default());
        print!(
            "{}.{:09}{}{}\n",
            timestamp.as_secs(),
            timestamp.subsec_nanos(),
            text,
            data_idx
        );
        buffered += 1;
        if buffered >= buffer_size {
            let _ = stdout().flush();
            buffered = 0;
        }

        // go to next packet
        packet_idx += 1;
        if packet_idx >= num_packets {
            packet_idx = 0;
            data_idx += 1;
            data_bytes = data_idx.to_be_bytes();
        }

        current_time += sleep_dur;

        sleeper.sleep(sleep_dur);
    }
}

struct SpinSleeper {
    start: Instant,
}

impl SpinSleeper {
    pub fn new(start: Instant) -> Self {
        Self { start }
    }

    pub fn sleep(self, duration: Duration) {
        // only sleep when there is some duration left.
        if let Some(duration_left) = duration.checked_sub(self.start.elapsed()) {
            // do the native sleep
            if let Some(native_sleep) = duration_left.checked_sub(SLEEP_ACCURACY) {
                std::thread::sleep(native_sleep)
            }
            // do the spin sleep
            while self.start.elapsed() < duration {
                std::thread::yield_now()
            }
        }
    }
}
