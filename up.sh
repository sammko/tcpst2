#!/bin/bash
if [ -z "$SUDO_USER" ]; then
    echo "Run under sudo"
    exit 1
fi

NAME="tun-st"

set -eux

ip tuntap add dev "$NAME" mode tun user "$SUDO_USER"
ip addr add 192.168.22.100/24 dev "$NAME"
ip link set dev "$NAME" up
ip -d link show "$NAME"