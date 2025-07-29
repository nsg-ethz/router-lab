#!/bin/bash

# specify interfaces to run the delayer on as arguments

TMUX_SESSION=delayers

echo "Using interfaces: $@"
echo "Tmux session: ${TMUX_SESSION}"

tmux kill-session -t "${TMUX_SESSION}" 2>/dev/null
tmux new -s "${TMUX_SESSION}" -d

# abuse this file to also disable hardware offloads on the mellanox nics:
# tcp-segmentation-offload: off
# generic-segmentation-offload: off
# generic-receive-offload: off
# large-receive-offload: off
sudo ethtool -K "enp132s0f0" tso off gso off gro off lro off
sudo ethtool -K "enp132s0f1" tso off gso off gro off lro off
# can be verified using
#sudo ethtool -k "${iface}"


for iface in "$@"; do
	echo "${iface}:"

	# set the interface to promiscuous mode
	echo "- enabling promiscuous mode"
	sudo ip link set "${iface}" promisc on

	# increase NIC RX buffer
	echo "- increasing NIC's buffer size"
	sudo ethtool -G "${iface}" rx 1024
	sudo ethtool -G "${iface}" tx 1024

	echo "- launching delayer (busy-wait)"
	tmux split-window -p 90
	tmux send-keys -t "${TMUX_SESSION}" "sudo delayer \"${iface}\" --spin" Enter

	echo ""
done
