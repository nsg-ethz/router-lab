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
    cmp::Reverse,
    collections::BinaryHeap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, UNIX_EPOCH},
};

use clap::Parser;
use crossbeam::channel::{bounded, Receiver, RecvTimeoutError, Sender};
use libc::timeval;

mod raw_socket;
use raw_socket::{
    create_socket, iface_disable_promisc_mode, iface_enable_promisc_mode, recv_pkt, send_pkt,
};
mod raw_time;
use raw_time::{tv_add, usec_to_tv};

pub type RawPacket = Vec<u8>;

const PRECISION: Duration = Duration::from_nanos(125_000);

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Do not use os sleep, but use a spin loop
    #[clap(short, long)]
    spin: bool,
    /// Interface name to delay packets on.
    iface: String,
}

#[allow(clippy::needless_collect)]
fn main() {
    let Args { iface, spin } = Args::parse();

    // handle process signals to disable promisc mode again.
    let kill = Arc::new(AtomicBool::new(false));
    let kill_output = kill.clone();
    let kill_input = kill.clone();
    signal_hook::flag::register(signal_hook::consts::SIGINT, kill.clone()).unwrap();
    signal_hook::flag::register(signal_hook::consts::SIGTERM, kill.clone()).unwrap();
    signal_hook::flag::register(signal_hook::consts::SIGQUIT, kill.clone()).unwrap();

    // create the channel
    let (tx, rx) = bounded(4096);

    // create the socket
    let socket = create_socket(&iface);

    // enable promisc mode
    iface_enable_promisc_mode(socket, &iface);

    // start the threads
    let output_handle = std::thread::spawn(move || output(socket, rx, kill_output, spin));
    let input_handle = std::thread::spawn(move || input(socket, tx, kill_input));

    let _ = output_handle.join();
    let _ = input_handle.join();

    // disable promisc mode
    iface_disable_promisc_mode(socket, &iface);
}

pub fn input(socket: i32, channel: Sender<Pkt>, kill: Arc<AtomicBool>) {
    // start the endless loop
    while !kill.load(Ordering::Relaxed) {
        // wait for the next packet
        let p = recv_pkt(socket);
        // process the packet
        if let Some(p) = process_pkt(p) {
            // check if the channel is full
            if channel.is_full() {
                eprintln!("[INPUT]  channel is full! dropping packet.")
            } else {
                match channel.send(p) {
                    Ok(()) => {}
                    Err(_) => {
                        eprintln!("[INPUT]  Channel is dead! exiting...");
                        return;
                    }
                }
            }
        } else {
            // ignoring a non-delay packet.
        }
    }
}

pub fn process_pkt(data: (RawPacket, timeval)) -> Option<Pkt> {
    let (pkt, recv_tv) = data;
    // check if the packet has length at least 18 bytes long
    if pkt.len() < 18 {
        return None;
    }
    // check that the packet ethertype is proper.
    if pkt[12..=13] != [0xde, 0xad] {
        return None;
    }

    // packet is of the kind we expect.
    // extract the microsecond delay
    let delay_us = ((pkt[14] as u32) << 15) + ((pkt[15] as u32) << 7) + ((pkt[16] >> 1) as u32);
    let delay_tv = usec_to_tv(delay_us as i64);
    let trigger_tv = tv_add(recv_tv, delay_tv);
    let deadline = Duration::new(trigger_tv.tv_sec as u64, trigger_tv.tv_usec as u32 * 1000);

    let now = UNIX_EPOCH.elapsed().unwrap();
    if deadline < now {
        let diff = now.saturating_sub(deadline);
        if diff.as_millis() > 1 {
            eprintln!(
                "[INPUT] Cannot keep up with the demand! Packet should already be sent since {}s",
                diff.as_secs_f64()
            );
        }
    }

    Some(Pkt {
        pkt,
        deadline: Reverse(deadline),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkt {
    pkt: Vec<u8>,
    /// As duration since unix epoch
    deadline: Reverse<Duration>,
}

impl Ord for Pkt {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

impl PartialOrd for Pkt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.deadline.partial_cmp(&other.deadline)
    }
}

pub fn output(socket: i32, channel: Receiver<Pkt>, kill: Arc<AtomicBool>, spin: bool) {
    if spin {
        output_spin(socket, channel, kill)
    } else {
        output_sleep(socket, channel, kill)
    }
}

pub fn output_spin(socket: i32, channel: Receiver<Pkt>, kill: Arc<AtomicBool>) {
    // setup the queue
    let mut queue: BinaryHeap<Pkt> = BinaryHeap::new();

    // start the endless loop
    while !kill.load(Ordering::Relaxed) {
        let now = UNIX_EPOCH.elapsed().unwrap();

        if let Ok(pkt) = channel.try_recv() {
            if pkt.deadline.0 < now {
                let diff = now.saturating_sub(pkt.deadline.0);
                if diff.as_millis() > 1 {
                    eprintln!("[OUTPUT] Cannot keep up with the the input! packet shoudl be sent {:.6}s ago", diff.as_secs_f64());
                }
            }
            queue.push(pkt)
        }

        if let Some(pkt) = queue.peek() {
            // spin sleep until we need to send the packet
            if now >= pkt.deadline.0 {
                let _ = send_pkt(socket, queue.pop().unwrap().pkt);
            }
        }

        std::hint::spin_loop();
    }
}

pub fn output_sleep(socket: i32, channel: Receiver<Pkt>, kill: Arc<AtomicBool>) {
    // setup the queue
    let mut queue: BinaryHeap<Pkt> = BinaryHeap::new();

    // start the endless loop
    while !kill.load(Ordering::Relaxed) {
        // get the timeout for the next packet
        let now = UNIX_EPOCH.elapsed().unwrap();

        let deadline = queue
            .peek()
            .map(|p| p.deadline.0)
            .unwrap_or_else(|| now + Duration::from_secs(60));

        let timeout = deadline.saturating_sub(now);

        if timeout.is_zero() {
            let diff = now.saturating_sub(deadline);
            if diff.as_millis() > 1 {
                eprintln!(
                    "[OUTPUT] Enqueued packet should have been sent in the past! ({:.6}s too late)",
                    diff.as_secs_f64()
                );
            }
        };

        match channel.recv_timeout(timeout.saturating_sub(PRECISION)) {
            Ok(pkt) => {
                if pkt.deadline.0 < now {
                    let diff = now.saturating_sub(pkt.deadline.0);
                    if diff.as_millis() > 1 {
                        eprintln!("[OUTPUT] Cannot keep up with the the input! packet shoudl be sent {:.6}s ago", diff.as_secs_f64());
                    }
                }
                queue.push(pkt)
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Some(pkt) = queue.pop() {
                    // spin sleep until we need to send the packet
                    while UNIX_EPOCH.elapsed().unwrap() < pkt.deadline.0 {
                        std::hint::spin_loop();
                    }
                    let _ = send_pkt(socket, pkt.pkt);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                eprintln!("[OUTPUT] Channel is dead! exiting...");
                return;
            }
        }
    }
}
