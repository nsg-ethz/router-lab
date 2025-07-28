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
{{PORT_LIST}}

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
{{DELAY_ROUTES}}
}
use_delayer = True

# Static routes do overwrite other routing mechanisms.
#
# Usage:
#   <ingress port number>:  {'port': <egress port number>},
rules_static_route = {
{{STATIC_ROUTES}}
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
{{L2_RULES}}
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
rules_mirror_all = {{MIRROR_ALL}}

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
{{IPERF_REPLICATION_SPECS}}
}
traffic_replication_filter_src_ip = "{{IPERF_FILTER_SRC_IP}}"
traffic_replication_client_port = {{IPERF_CLIENT_PORT}}
traffic_replication_server_port = {{IPERF_SERVER_PORT}}


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
