# RouterLab: Orchestration Layer to Automate Experiments on Network Routers
# Copyright (C) 2022-2025 Tibor Schneider <sctibor@ethz.ch> and Roland Schmid <roschmi@ethz.ch>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from netaddr import IPAddress, EUI

##############################################################################################
################################## Populating Table Entries ##################################
##############################################################################################

# This list of port numbers is passed as a multicast group used for L2-broadcasting (e.g. ARP).
ports_list = [
    # Router lab-vdc111
    132, 140, 133, 141, 134, 142, 145, 143, 148, 156, 149, 157, 150, 158, 151, 159,
    # Router lab-vdc112
    164, 172, 165, 173, 166, 174, 167, 175, 180, 188, 181, 189, 182, 190, 183,
    # Router lab-vdc113
    56, 48, 57, 49, 58, 50, 59, 51, 40, 32, 41, 33, 42, 34,
    # Router lab-vdc114
    24, 16, 25, 17, 26, 18, 27, 19, 8, 4, 9, 5, 10,
    # Router lab-vdc121
    4, 12, 5, 13, 6, 14, 7, 15, 20, 28, 21, 29,
    # Router lab-vdc122
    36, 44, 37, 45, 38, 46, 39, 47, 52, 60, 53,
    # Router lab-vdc123
    184, 176, 185, 177, 186, 178, 187, 179, 168, 160,
    # Router lab-vdc124
    144, 152, 145, 153, 146, 154, 147, 155, 128,

    # server-side
    #128, 129, # 2x 10G
    #136, 137, # 2x 10G
    #138, # 10G: iperf client in netns
    #139, # 10G: iperf server

    # moonshine
    36, # 100G: exabgp, prober
    #44, # 100G: traffic-mirror for all traffic
    #52, 53, 54, 55, # 3x 10G: delayers
]

# Delay has precedence over routing and includes forwarding along a static route once the packet
# comes back from the delayer.
#
# Usage:
#   <ingress port number>:  {
#       'src_addr': <src MAC for delay packets>,
#       'dst_addr': <dst MAC for delay packets>,
#       'delay': <bit<23> specifying delay>,
#       'base_delay_port': <port on which to forward traffic to a delayer instance>,
#       'receiver_port': <port on which to forward traffic after delaying it>
#   },
rules_delay = {

}
use_delayer = True

# Static routes do overwrite other routing mechanisms.
#
# Usage:
#   <ingress port number>:  {'port': <egress port number>},
rules_static_route = {
}

# Do not forward traffic from these IP addresses, except for static_routes (including delayed packets).
#
# Usage:
#   IPAddress("A.B.C.D")
rules_ipv4_filter = []

# Second priority in the routing hierarchy.
#
# Usage:
#   IPAddress("A.B.C.D"):  {'port': <egress port number>},
rules_ipv4_route = {
}

# Third priority in the routing hierarchy.
#
# Usage:
#   EUI("aa:bb:cc:dd:ee:ff"):  {'port': <egress port number>},
#
# Note: The broadcast address "ff:ff:ff:ff:ff:ff" is handled already.
rules_l2_route = {
    # Router lab-vdc111
    EUI("de:ad:00:6f:04:01"): {'port': 132},
    EUI("de:ad:00:6f:04:02"): {'port': 140},
    EUI("de:ad:00:6f:04:03"): {'port': 133},
    EUI("de:ad:00:6f:04:04"): {'port': 141},
    EUI("de:ad:00:6f:04:05"): {'port': 134},
    EUI("de:ad:00:6f:04:06"): {'port': 142},
    EUI("de:ad:00:6f:04:07"): {'port': 145},
    EUI("de:ad:00:6f:04:08"): {'port': 143},
    EUI("de:ad:00:6f:04:09"): {'port': 148},
    EUI("de:ad:00:6f:04:0a"): {'port': 156},
    EUI("de:ad:00:6f:04:0b"): {'port': 149},
    EUI("de:ad:00:6f:04:0c"): {'port': 157},
    EUI("de:ad:00:6f:04:0d"): {'port': 150},
    EUI("de:ad:00:6f:04:0e"): {'port': 158},
    EUI("de:ad:00:6f:04:0f"): {'port': 151},
    EUI("de:ad:00:6f:04:10"): {'port': 159},

    # Router lab-vdc112
    EUI("de:ad:00:70:04:19"): {'port': 164},
    EUI("de:ad:00:70:04:1a"): {'port': 172},
    EUI("de:ad:00:70:04:1b"): {'port': 165},
    EUI("de:ad:00:70:04:1c"): {'port': 173},
    EUI("de:ad:00:70:04:1d"): {'port': 166},
    EUI("de:ad:00:70:04:1e"): {'port': 174},
    EUI("de:ad:00:70:04:1f"): {'port': 167},
    EUI("de:ad:00:70:04:20"): {'port': 175},
    EUI("de:ad:00:70:04:21"): {'port': 180},
    EUI("de:ad:00:70:04:22"): {'port': 188},
    EUI("de:ad:00:70:04:23"): {'port': 181},
    EUI("de:ad:00:70:04:24"): {'port': 189},
    EUI("de:ad:00:70:04:25"): {'port': 182},
    EUI("de:ad:00:70:04:26"): {'port': 190},
    EUI("de:ad:00:70:04:27"): {'port': 183},

    # Router lab-vdc113
    EUI("de:ad:00:71:06:01"): {'port': 56},
    EUI("de:ad:00:71:06:02"): {'port': 48},
    EUI("de:ad:00:71:06:03"): {'port': 57},
    EUI("de:ad:00:71:06:04"): {'port': 49},
    EUI("de:ad:00:71:06:05"): {'port': 58},
    EUI("de:ad:00:71:06:06"): {'port': 50},
    EUI("de:ad:00:71:06:07"): {'port': 59},
    EUI("de:ad:00:71:06:08"): {'port': 51},
    EUI("de:ad:00:71:06:09"): {'port': 40},
    EUI("de:ad:00:71:06:0a"): {'port': 32},
    EUI("de:ad:00:71:06:0b"): {'port': 41},
    EUI("de:ad:00:71:06:0c"): {'port': 33},
    EUI("de:ad:00:71:06:0d"): {'port': 42},
    EUI("de:ad:00:71:06:0e"): {'port': 34},

    # Router lab-vdc114
    EUI("de:ad:00:72:08:01"): {'port': 24},
    EUI("de:ad:00:72:08:02"): {'port': 16},
    EUI("de:ad:00:72:08:03"): {'port': 25},
    EUI("de:ad:00:72:08:04"): {'port': 17},
    EUI("de:ad:00:72:08:05"): {'port': 26},
    EUI("de:ad:00:72:08:06"): {'port': 18},
    EUI("de:ad:00:72:08:07"): {'port': 27},
    EUI("de:ad:00:72:08:08"): {'port': 19},
    EUI("de:ad:00:72:08:09"): {'port': 8},
    EUI("de:ad:00:72:08:0a"): {'port': 4},
    EUI("de:ad:00:72:08:0b"): {'port': 9},
    EUI("de:ad:00:72:08:0c"): {'port': 5},
    EUI("de:ad:00:72:08:0d"): {'port': 10},

    # Router lab-vdc121
    EUI("de:ad:00:79:05:01"): {'port': 4},
    EUI("de:ad:00:79:05:02"): {'port': 12},
    EUI("de:ad:00:79:05:03"): {'port': 5},
    EUI("de:ad:00:79:05:04"): {'port': 13},
    EUI("de:ad:00:79:05:05"): {'port': 6},
    EUI("de:ad:00:79:05:06"): {'port': 14},
    EUI("de:ad:00:79:05:07"): {'port': 7},
    EUI("de:ad:00:79:05:08"): {'port': 15},
    EUI("de:ad:00:79:05:09"): {'port': 20},
    EUI("de:ad:00:79:05:0a"): {'port': 28},
    EUI("de:ad:00:79:05:0b"): {'port': 21},
    EUI("de:ad:00:79:05:0c"): {'port': 29},

    # Router lab-vdc122
    EUI("de:ad:00:7a:05:19"): {'port': 36},
    EUI("de:ad:00:7a:05:1a"): {'port': 44},
    EUI("de:ad:00:7a:05:1b"): {'port': 37},
    EUI("de:ad:00:7a:05:1c"): {'port': 45},
    EUI("de:ad:00:7a:05:1d"): {'port': 38},
    EUI("de:ad:00:7a:05:1e"): {'port': 46},
    EUI("de:ad:00:7a:05:1f"): {'port': 39},
    EUI("de:ad:00:7a:05:20"): {'port': 47},
    EUI("de:ad:00:7a:05:21"): {'port': 52},
    EUI("de:ad:00:7a:05:22"): {'port': 60},
    EUI("de:ad:00:7a:05:23"): {'port': 53},

    # Router lab-vdc123
    EUI("de:ad:00:7b:06:01"): {'port': 184},
    EUI("de:ad:00:7b:06:02"): {'port': 176},
    EUI("de:ad:00:7b:06:03"): {'port': 185},
    EUI("de:ad:00:7b:06:04"): {'port': 177},
    EUI("de:ad:00:7b:06:05"): {'port': 186},
    EUI("de:ad:00:7b:06:06"): {'port': 178},
    EUI("de:ad:00:7b:06:07"): {'port': 187},
    EUI("de:ad:00:7b:06:08"): {'port': 179},
    EUI("de:ad:00:7b:06:09"): {'port': 168},
    EUI("de:ad:00:7b:06:0a"): {'port': 160},

    # Router lab-vdc124
    EUI("de:ad:00:7c:06:19"): {'port': 144},
    EUI("de:ad:00:7c:06:1a"): {'port': 152},
    EUI("de:ad:00:7c:06:1b"): {'port': 145},
    EUI("de:ad:00:7c:06:1c"): {'port': 153},
    EUI("de:ad:00:7c:06:1d"): {'port': 146},
    EUI("de:ad:00:7c:06:1e"): {'port': 154},
    EUI("de:ad:00:7c:06:1f"): {'port': 147},
    EUI("de:ad:00:7c:06:20"): {'port': 155},
    EUI("de:ad:00:7c:06:21"): {'port': 128},

    # server-side config
    #EUI("64:9d:99:b1:ad:5b"): {'port': 136},
    #EUI("64:9d:99:b1:ad:5c"): {'port': 137},
    #EUI("64:9d:99:b1:ad:5d"): {'port': 138},
    #EUI("64:9d:99:b1:ad:5e"): {'port': 139},
    #EUI("f8:f2:1e:41:44:9d"): {'port': 128},
    #EUI("f8:f2:1e:41:44:9c"): {'port': 129},

    # moonshine config
    EUI("08:c0:eb:6f:f5:26"): {'port': 36},
    #EUI("08:c0:eb:6f:f5:27"): {'port': 44},
    #EUI("64:9d:99:b1:ad:9b"): {'port': 52},
    #EUI("64:9d:99:b1:ad:9c"): {'port': 53},
    #EUI("64:9d:99:b1:ad:9d"): {'port': 54},
    #EUI("64:9d:99:b1:ad:9e"): {'port': 55},
}

# Least prioritized routing mechanism.
#
# Usage:
#   <ingress port number>:  {'port': <egress port number>},
rules_fallback_route = {
}

## debug port is used for all packets that do not match any routing and would otherwise be dropped
debug_port = None

# Mirror packets to <mirror_port> according to TCP's src/dst port.
#
# Usage:
#   <TCP port>:  {'mirror_session': <mirror_session_id>, 'mirror_port': <mirror_port>},
rules_tcp_mirror = {
    # BGP mirroring
    #179: {'mirror_session': 1, 'mirror_port': 138},
}

# Mirror packets to <mirror_port> according to src and dst IP.
#
# Usage:
#   <(src IP, dst IP)>:  {'mirror_session': <mirror_session_id>, 'mirror_port': <mirror_port>},
rules_ip_mirror = {
}

# Mirror packets to <mirror_port> according to src and dst MAC.
#
# Usage:
#   <(src MAC, dst MAC)>:  {'mirror_session': <mirror_session_id>, 'mirror_port': <mirror_port>},
rules_l2_mirror = {
    # prober traffic sent to vdc111
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:6f:04:01")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:6f:04:02")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:6f:04:03")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:6f:04:04")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:6f:04:05")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:6f:04:06")): {'mirror_session': 2, 'mirror_port': 138},

    # prober traffic sent to vdc121
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:79:05:01")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:79:05:02")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:79:05:03")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:be:ef:00:00"), EUI("de:ad:00:79:05:04")): {'mirror_session': 2, 'mirror_port': 138},

    # prober traffic from vdc121 on the last hop
#   (EUI("de:ad:00:79:05:01"), EUI("08:c0:eb:6f:f5:26")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:00:79:05:02"), EUI("08:c0:eb:6f:f5:26")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:00:79:05:03"), EUI("08:c0:eb:6f:f5:26")): {'mirror_session': 2, 'mirror_port': 138},
#   (EUI("de:ad:00:79:05:04"), EUI("08:c0:eb:6f:f5:26")): {'mirror_session': 2, 'mirror_port': 138},
}

# Mirror all packets to <mirror_port>.
#
# Usage:
#   - to enable, use:
#     rules_mirror_all = {'mirror_session': <mirror_session_id>, 'mirror_port': <mirror_port>},
#   - to disable, use:
#     rules_mirror_all = None
rules_mirror_all = None

# Rewriting src MAC address based on the destination IP.
#
# Usage:
#   IPAddress("A.B.C.D"):  {'src_mac': EUI("aa:bb:cc:dd:ee:ff")},
rules_ipv4_host_src_mac = {
}

# Rewriting dst MAC address based on the destination IP.
#
# Usage:
#   IPAddress("A.B.C.D"):  {'dst_mac': EUI("aa:bb:cc:dd:ee:ff")},
rules_ipv4_host_dst_mac = {
}

# Rewriting src and dst MAC address based on the destination IP.
#
# Usage:
#   IPAddress("A.B.C.D"):  {'src_mac': EUI("aa:bb:cc:dd:ee:ff"), 'dst_mac': EUI("aa:bb:cc:dd:ee:ff")},
rules_ipv4_host_src_and_dst_mac = {
}

# Replicate data-plane traffic to all of the following ports, with rewriting the src and dst MAC and IPv4 addresses.
#
# Usage:
#   <egress port number>:  {'dst_mac': EUI("aa:bb:cc:dd:ee:ff"), 'dst_ip': IPAddress("A.B.C.D")},
rules_traffic_replication = {
    132: {'dst_mac': EUI("de:ad:00:6f:04:01"), 'dst_ip': IPAddress("1.128.0.6")},
    133: {'dst_mac': EUI("de:ad:00:6f:04:03"), 'dst_ip': IPAddress("1.128.0.14")},
    134: {'dst_mac': EUI("de:ad:00:6f:04:05"), 'dst_ip': IPAddress("1.128.0.2")},
    140: {'dst_mac': EUI("de:ad:00:6f:04:02"), 'dst_ip': IPAddress("1.128.0.10")},
    141: {'dst_mac': EUI("de:ad:00:6f:04:04"), 'dst_ip': IPAddress("1.192.0.2")},
    164: {'dst_mac': EUI("de:ad:00:70:04:19"), 'dst_ip': IPAddress("1.128.0.18")},
    165: {'dst_mac': EUI("de:ad:00:70:04:1b"), 'dst_ip': IPAddress("1.128.0.26")},
    166: {'dst_mac': EUI("de:ad:00:70:04:1d"), 'dst_ip': IPAddress("1.128.0.5")},
    16: {'dst_mac': EUI("de:ad:00:72:08:02"), 'dst_ip': IPAddress("1.128.0.33")},
    172: {'dst_mac': EUI("de:ad:00:70:04:1a"), 'dst_ip': IPAddress("1.128.0.22")},
    173: {'dst_mac': EUI("de:ad:00:70:04:1c"), 'dst_ip': IPAddress("1.192.0.6")},
    17: {'dst_mac': EUI("de:ad:00:72:08:04"), 'dst_ip': IPAddress("1.128.0.13")},
    24: {'dst_mac': EUI("de:ad:00:72:08:01"), 'dst_ip': IPAddress("1.128.0.25")},
    25: {'dst_mac': EUI("de:ad:00:72:08:03"), 'dst_ip': IPAddress("1.128.0.38")},
    48: {'dst_mac': EUI("de:ad:00:71:06:02"), 'dst_ip': IPAddress("1.128.0.30")},
    49: {'dst_mac': EUI("de:ad:00:71:06:04"), 'dst_ip': IPAddress("1.128.0.9")},
    56: {'dst_mac': EUI("de:ad:00:71:06:01"), 'dst_ip': IPAddress("1.128.0.21")},
    57: {'dst_mac': EUI("de:ad:00:71:06:03"), 'dst_ip': IPAddress("1.128.0.34")},
}
traffic_replication_filter_src_ip = "192.33.88.220"
traffic_replication_client_port = 138
traffic_replication_server_port = 139


##############################################################################################
################################## Populating Table Entries ##################################
##############################################################################################

p4 = bfrt.simple_router.pipe
Ingress = p4.Ingress
Egress = p4.Egress

# setting up multicast group to enable ARP
bfrt.pre.node.entry(
    MULTICAST_NODE_ID=0x01, # BROADCAST_MGID
    MULTICAST_RID=0xFFFF, # L2_MCAST_RID
    MULTICAST_LAG_ID=[],
    DEV_PORT=ports_list).push()
bfrt.pre.mgid.entry(
    MGID=0x01,
    MULTICAST_NODE_ID=[0x01],
    MULTICAST_NODE_L1_XID_VALID=[0],
    MULTICAST_NODE_L1_XID=[0]).push()

# setting up multicast groups for data-plane traffic replication
# multicast client's message to all registered ports and the server
bfrt.pre.node.entry(
    MULTICAST_NODE_ID=0x02, # TRAFFIC_REPLICATION_MGID_CLIENT
    MULTICAST_RID=0xFFFE, # TRAFFIC_MCAST_RID_CLIENT
    MULTICAST_LAG_ID=[],
    DEV_PORT=[traffic_replication_server_port] + list(rules_traffic_replication.keys())).push()
bfrt.pre.mgid.entry(
    MGID=0x02,
    MULTICAST_NODE_ID=[0x02],
    MULTICAST_NODE_L1_XID_VALID=[0],
    MULTICAST_NODE_L1_XID=[0]).push()

# fill Ingress table(s)
Ingress.delay.clear()
if use_delayer:
    for key in rules_delay:
        Ingress.delay.add_with_send_delayed(key, **rules_delay[key])

Ingress.static_route.clear()
for key in rules_static_route:
    Ingress.static_route.add_with_send(key, **rules_static_route[key])
# replicate data-plane traffic
Ingress.static_route.add_with_replicate_traffic_client(ingress_port=traffic_replication_client_port)
Ingress.static_route.add_with_send(ingress_port=traffic_replication_server_port, port=traffic_replication_client_port)
if rules_mirror_all:
    Ingress.static_route.add_with_drop(ingress_port=rules_mirror_all['mirror_port'])

Ingress.ipv4_filter.clear()
for key in rules_ipv4_filter:
    Ingress.ipv4_filter.add_with_drop(key)
# drop replicated data-plane traffic returning back to the Tofino
Ingress.ipv4_filter.add_with_drop(IPAddress(traffic_replication_filter_src_ip))

Ingress.ipv4_route.clear()
for key in rules_ipv4_route:
    Ingress.ipv4_route.add_with_send(key, **rules_ipv4_route[key])

Ingress.l2_route.clear()
for key in rules_l2_route:
    Ingress.l2_route.add_with_send(key, **rules_l2_route[key])
Ingress.l2_route.add_with_broadcast(dst_addr=EUI("ff:ff:ff:ff:ff:ff"))

Ingress.fallback_route.clear()
for key in rules_fallback_route:
    Ingress.fallback_route.add_with_send(key, **rules_fallback_route[key])
if debug_port:
    Ingress.fallback_route.set_default_with_send(debug_port)

Ingress.tcp_src_mirror.clear()
Ingress.tcp_dst_mirror.clear()
for key in rules_tcp_mirror:
    mirror_session = rules_tcp_mirror[key]['mirror_session']
    try:
        bfrt.mirror.cfg.delete(mirror_session)
    except BfRtTableError:
        pass # probably no entry exists
    # setup mirror session to mirror TCP packets matching port to the mirror_port specified
    bfrt.mirror.cfg.add_with_normal(
        sid=mirror_session, session_enable=True, direction='BOTH',
        ucast_egress_port=rules_tcp_mirror[key]['mirror_port'], ucast_egress_port_valid=True,
        max_pkt_len=16384)
    # fill Ingress table
    Ingress.tcp_src_mirror.add_with_do_tcp_mirror(key, mirror_session=mirror_session)
    Ingress.tcp_dst_mirror.add_with_do_tcp_mirror(key, mirror_session=mirror_session)

Ingress.ip_mirror.clear()
for key in rules_ip_mirror:
    mirror_session = rules_ip_mirror[key]['mirror_session']
    try:
        bfrt.mirror.cfg.delete(mirror_session)
    except BfRtTableError:
        pass # probably no entry exists
    # setup mirror session to mirror TCP packets matching port to the mirror_port specified
    bfrt.mirror.cfg.add_with_normal(
        sid=mirror_session, session_enable=True, direction='BOTH',
        ucast_egress_port=rules_ip_mirror[key]['mirror_port'], ucast_egress_port_valid=True,
        max_pkt_len=16384)
    # fill Ingress table
    Ingress.ip_mirror.add_with_do_ip_mirror(*key, mirror_session=mirror_session)

Ingress.l2_mirror.clear()
for key in rules_l2_mirror:
    mirror_session = rules_l2_mirror[key]['mirror_session']
    try:
        bfrt.mirror.cfg.delete(mirror_session)
    except BfRtTableError:
        pass # probably no entry exists
    # setup mirror session to mirror TCP packets matching port to the mirror_port specified
    bfrt.mirror.cfg.add_with_normal(
        sid=mirror_session, session_enable=True, direction='BOTH',
        ucast_egress_port=rules_l2_mirror[key]['mirror_port'], ucast_egress_port_valid=True,
        max_pkt_len=16384)
    # fill Ingress table
    Ingress.l2_mirror.add_with_do_l2_mirror(*key, mirror_session=mirror_session)

Ingress.mirror_all.clear()
if rules_mirror_all:
    mirror_session = rules_mirror_all['mirror_session']
    try:
        bfrt.mirror.cfg.delete(mirror_session)
    except BfRtTableError:
        pass # probably no entry exists
    # setup mirror session to mirror TCP packets matching port to the mirror_port specified
    bfrt.mirror.cfg.add_with_normal(
        sid=mirror_session, session_enable=True, direction='BOTH',
        ucast_egress_port=rules_mirror_all['mirror_port'], ucast_egress_port_valid=True,
        max_pkt_len=16384)
    # fill Ingress table
    Ingress.mirror_all.set_default_with_do_mirror_all(mirror_session=mirror_session)

# fill Egress table(s)
Egress.static_host_for_multicast_traffic.clear()
for key in rules_traffic_replication:
    # add rules for TRAFFIC_REPLICATION_MGID_CLIENT
    Egress.static_host_for_multicast_traffic.add_with_set_l2_and_l3_src_and_dst_addr(0xFFFE, key, src_mac=EUI("de:ad:be:ef:de:ad"), src_ip=IPAddress(traffic_replication_filter_src_ip), **rules_traffic_replication[key])
    # no rewrite required for client/server, as they are basically connected directly with a static route

Egress.ipv4_host.clear()
for key in rules_ipv4_host_src_mac:
    Egress.ipv4_host.add_with_set_l2_src_addr(key, **rules_ipv4_host_src_mac[key])
for key in rules_ipv4_host_dst_mac:
    Egress.ipv4_host.add_with_set_l2_dst_addr(key, **rules_ipv4_host_dst_mac[key])
for key in rules_ipv4_host_src_and_dst_mac:
    Egress.ipv4_host.add_with_set_l2_src_and_dst_addr(key, **rules_ipv4_host_src_and_dst_mac[key])

bfrt.complete_operations()
