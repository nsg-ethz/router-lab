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

use std::{
    mem::{size_of, transmute},
    ptr::null,
};

use libc::{
    bind, c_void, ifreq, ioctl, sendto, sockaddr, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL,
    PF_PACKET, SIOCGIFINDEX, SOCK_RAW,
};

use crate::RawPacket;

pub fn create_socket(iface: &str) -> i32 {
    // create the socket
    let sock = unsafe { socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32) };
    assert!(sock >= 0, "Cannot create the socket!");

    // get the iface id
    let ifindex = iface_to_id(sock, iface);

    // bind to device
    iface_bind_to_device(sock, ifindex, htons(ETH_P_ALL as u16));

    sock
}

pub fn send_pkt(sock: i32, pkt: &RawPacket) {
    let bytes = pkt.len();

    // send here
    let bytes_sent = unsafe { sendto(sock, pkt.as_ptr() as *const c_void, bytes, 0, null(), 0) };
    assert!(
        bytes_sent == bytes as isize,
        "Could not send the packet properly"
    );
}

fn htons(u: u16) -> u16 {
    u.to_be()
}

fn iface_to_id(sock: i32, iface: &str) -> i32 {
    let mut ifr = ifreq {
        ifr_name: iface_name_as_slice(iface),
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_ifindex: 0 },
    };

    let ret = unsafe { ioctl(sock, SIOCGIFINDEX, &mut ifr) };
    assert!(ret >= 0, "failed to get interface index!");

    let ifindex = unsafe { ifr.ifr_ifru.ifru_ifindex };

    ifindex
}

fn iface_name_as_slice(iface: &str) -> [i8; 16] {
    let bytes = iface.as_bytes();
    assert!(bytes.len() <= 16, "Iface name is larger than 16!");
    let mut i = 0;
    [0; 16].map(|_| {
        let x = bytes.get(i).copied().unwrap_or(0);
        i += 1;
        unsafe { transmute(x) }
    })
}

fn iface_bind_to_device(sock: i32, ifindex: i32, protocol: u16) {
    let sll = sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: protocol,
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let ret = unsafe {
        bind(
            sock,
            (&sll) as *const sockaddr_ll as *const sockaddr,
            size_of::<sockaddr_ll>() as u32,
        )
    };
    assert!(ret >= 0, "Cannot bind socket to interface");
}
