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
    ffi::c_int,
    mem::{size_of, transmute, MaybeUninit},
    ptr::{null, null_mut},
};

use libc::{
    bind, c_void, ifreq, ioctl, iovec, memcpy, msghdr, recvmsg, sendto, setsockopt, sockaddr,
    sockaddr_ll, socket, timeval, AF_PACKET, CMSG_DATA, CMSG_FIRSTHDR, CMSG_NXTHDR, ETH_P_ALL,
    IFF_PROMISC, PF_PACKET, SCM_TIMESTAMP, SIOCGIFFLAGS, SIOCGIFINDEX, SIOCSIFFLAGS, SOCK_RAW,
    SOL_SOCKET, SO_RCVBUFFORCE, SO_SNDBUFFORCE, SO_TIMESTAMP,
};

use crate::RawPacket;

const MAX_PACKET_SIZE: usize = 2048;
const CONTROL_SIZE: usize = 1024;

pub fn create_socket(iface: &str) -> i32 {
    // create the socket
    let sock = unsafe { socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32) };
    assert!(sock >= 0, "Cannot create the socket!");

    // get the iface id
    let ifindex = iface_to_id(sock, iface);

    // bind to device
    iface_bind_to_device(sock, ifindex, htons(ETH_P_ALL as u16));

    // enable timestamp ns
    enable_so_timestamp_ns(sock);

    // set the buffer size
    set_buffer_size(sock, 2048);

    println!("socket created successfully");

    sock
}

/// blocking request to receive a single packet
pub fn recv_pkt(sock: i32) -> (RawPacket, timeval) {
    let (buffer, _, cap) = Vec::<u8>::with_capacity(MAX_PACKET_SIZE).into_raw_parts();
    let mut control = MaybeUninit::<[u8; CONTROL_SIZE]>::uninit();

    let mut iov = iovec {
        iov_base: buffer as *mut c_void,
        iov_len: MAX_PACKET_SIZE,
    };

    let mut header = msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut c_void,
        msg_controllen: CONTROL_SIZE,
        msg_flags: 0,
    };

    let bytes_read = unsafe { recvmsg(sock, &mut header, 0) };

    assert!(bytes_read >= 0, "Cannot receive packets from the socket");

    let pkt = unsafe { Vec::from_raw_parts(buffer, bytes_read as usize, cap) };

    // receive the timestamp
    let timestamp = get_packet_timestamp(&header);

    (pkt, timestamp)
}

pub fn send_pkt(sock: i32, mut pkt: RawPacket) {
    let buffer = pkt.as_mut_ptr();
    let bytes = pkt.len();

    // send here
    let bytes_sent = unsafe { sendto(sock, buffer as *mut c_void, bytes, 0, null(), 0) };
    assert_eq!(
        bytes_sent, bytes as isize,
        "Could not send the packet properly"
    );

    // drop the bytes here.
    std::mem::drop(pkt)
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

    unsafe { ifr.ifr_ifru.ifru_ifindex }
}

pub fn iface_enable_promisc_mode(sock: i32, iface: &str) {
    let mut ifr = ifreq {
        ifr_name: iface_name_as_slice(iface),
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
    };

    let ret = unsafe { ioctl(sock, SIOCGIFFLAGS, &mut ifr) };
    assert!(ret >= 0, "failed to get the current interface flags");

    // if the flag is already enabled, exit here
    let mut flags = unsafe { ifr.ifr_ifru.ifru_flags };
    if flags & (IFF_PROMISC as i16) != 0 {
        return;
    }
    flags |= IFF_PROMISC as i16;
    ifr.ifr_ifru = libc::__c_anonymous_ifr_ifru { ifru_flags: flags };
    let ret = unsafe { ioctl(sock, SIOCSIFFLAGS, &mut ifr) };
    assert!(ret >= 0, "failed to enable promisc mode.");
}

pub fn iface_disable_promisc_mode(sock: i32, iface: &str) {
    let mut ifr = ifreq {
        ifr_name: iface_name_as_slice(iface),
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
    };

    let ret = unsafe { ioctl(sock, SIOCGIFFLAGS, &mut ifr) };
    assert!(ret >= 0, "failed to get the current interface flags");

    // if the flag is already disabled, exit here
    let mut flags = unsafe { ifr.ifr_ifru.ifru_flags };
    if flags & (IFF_PROMISC as i16) == 0 {
        return;
    }
    flags &= !(IFF_PROMISC as i16);
    ifr.ifr_ifru = libc::__c_anonymous_ifr_ifru { ifru_flags: flags };
    let ret = unsafe { ioctl(sock, SIOCSIFFLAGS, &mut ifr) };
    assert!(ret >= 0, "failed to disable promisc mode");
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

/// Set the buffer size in kilobytes
fn set_buffer_size(sock: i32, buffer_size_kb: u32) {
    let size: c_int = (buffer_size_kb * 1024) as c_int;
    let ret = unsafe {
        setsockopt(
            sock,
            SOL_SOCKET,
            SO_RCVBUFFORCE,
            (&size as *const c_int) as *const c_void,
            size_of::<c_int>() as u32,
        )
    };
    assert!(ret == 0, "Cannot set receive buffer size!");
    let ret = unsafe {
        setsockopt(
            sock,
            SOL_SOCKET,
            SO_SNDBUFFORCE,
            (&size as *const c_int) as *const c_void,
            size_of::<c_int>() as u32,
        )
    };
    assert!(ret == 0, "Cannot set send buffer size!");
}

fn enable_so_timestamp_ns(sock: i32) {
    let enabled: c_int = 1;
    let ret = unsafe {
        setsockopt(
            sock,
            SOL_SOCKET,
            SO_TIMESTAMP,
            (&enabled as *const c_int) as *const c_void,
            size_of::<c_int>() as u32,
        )
    };
    assert!(ret == 0, "Cannot enable timestamp on socket");
}

fn get_packet_timestamp(header: &msghdr) -> timeval {
    let mut received_tv = None;

    unsafe {
        let mut cmsg = CMSG_FIRSTHDR(header);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == SOL_SOCKET && (*cmsg).cmsg_type == SCM_TIMESTAMP {
                let p_data = CMSG_DATA(cmsg);
                let mut tv = MaybeUninit::<timeval>::uninit();
                memcpy(
                    tv.as_mut_ptr() as *mut c_void,
                    p_data as *mut c_void,
                    size_of::<timeval>(),
                );
                received_tv = Some(tv.assume_init());
            }
            cmsg = CMSG_NXTHDR(header, cmsg);
        }
    }

    received_tv.expect("Did not receive any timestamp!")
}
