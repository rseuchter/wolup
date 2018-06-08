#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Creation:    30.06.2013
# Last Update: 08.06.2018
#
# Copyright (c) 2013-2015 by Georg Kainzbauer <http://www.gtkdb.de>
# Copyright (c) 2017-2018 by Roland Seuchter
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse
import re
import socket
import ipaddress
import struct

class MacAddress:
    mac_matcher = re.compile(r'^([0-9a-f]{2}[.:-]?){5}[0-9a-f]{2}$')
    sanitizer = str.maketrans("", "", ".:-")

    def __init__(self, raw_address):
        self.raw_address = raw_address
        self.address = None
        address = raw_address.lower()
        if (MacAddress.mac_matcher.match(address)):
            self.address = address.translate(MacAddress.sanitizer)
        else:
            raise argparse.ArgumentTypeError("%r is not a mac address" % self.raw_address)

    def __str__(self):
        return ":".join([self.address.upper()[i:i+2] for i in range(0, len(self.address), 2)])

def guess_broadcast_address(prefix = 24):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 9))
        nic = ipaddress.ip_interface((s.getsockname()[0], prefix))
    return nic.network.broadcast_address.compressed

def fetch_args():
    parser = argparse.ArgumentParser(
                description="wolup - start computers through wake on lan",
                epilog="""
(c) 2013-2015 by Georg Kainzbauer <http://www.gtkdb.de>
(c) 2017-2018 by Roland Seuchter
""",
                formatter_class=argparse.RawDescriptionHelpFormatter
)
    parser.add_argument('mac_list', metavar='MAC', type=MacAddress, nargs='+',
                        help = 'a MAC address of six hex bytes optionally separated by dot, colon, or hyphen e.g. 14:29:DA:DA:DA:00')
    parser.add_argument('-b', metavar='BROADCASTIP', dest='broadcast_ip', type=ipaddress.IPv4Address,
                        help = '(broadcast) IPv4 address to use for sending the WOL signal')
    parser.add_argument('-g', '--guess-ip', action='store_true',
                        help = 'try figure out the broadcast address automatically')

    return parser.parse_args()

def main():
    args = fetch_args()

    broadcast_addresses = []
    if args.broadcast_ip:
        broadcast_addresses.append(args.broadcast_ip.compressed)
    if args.guess_ip:
        broadcast_addresses.append(guess_broadcast_address())
    if len(broadcast_addresses) == 0:
        broadcast_addresses.append('255.255.255.255') # "limited broadcast"

    for mac in args.mac_list:
        print("Waking up {0} ...".format(mac))

        # create magic packet
        magic_packet = ''.join(['FF' * 6, mac.address * 16])
        payload = bytes()
        for i in range(0, len(magic_packet), 2):
            payload += struct.pack('B', int(magic_packet[i:i+2], 16))

        # send magic packet
        datagramSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        datagramSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for b in broadcast_addresses:
            bytes_sent = datagramSocket.sendto(payload, (b, 9))
            print("Sent %d bytes to %s" % (bytes_sent, b))

if __name__ == '__main__':
    main()
