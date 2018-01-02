#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Creation:    30.06.2013
# Last Update: 07.04.2015
#
# Copyright (c) 2013-2015 by Georg Kainzbauer <http://www.gtkdb.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#

# import required modules
import re
import socket
import struct
import sys

# main function
def main():
  # check syntax and print usage
  if len(sys.argv) != 2 or sys.argv[1] == '-h' or sys.argv[1] == '--help':
    print("Usage:\n\twake-on-lan.py <mac-address>\n")
    print("The MAC address could be specified in the following formats:")
    print("\t00:11:22:33:44:55\n\t00-11-22-33-44-55\n\t001122334455\n")
    print("(c) 2013 by Georg Kainzbauer <http://www.gtkdb.de>\n")
    sys.exit(1)

  # extract mac address from argument
  arg = sys.argv[1]
  if len(arg) == 12:
    mac = arg
  elif len(arg) == 17:
    mac = arg.replace(arg[2], '')
  else:
    print("ERROR: Invalid length of MAC address")
    sys.exit(1)

  # check specified MAC address
  if not re.search('[0-9a-fA-F]{12}', mac):
    print("ERROR: Invalid MAC address specified")
    sys.exit(1)

  # create magic packet
  magic_packet = ''.join(['FF' * 6, mac * 16])
  send_data = ''
  for i in range(0, len(magic_packet), 2):
    send_data = ''.join([send_data, struct.pack('B', int(magic_packet[i: i + 2], 16))])

  # send magic packet
  dgramSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  dgramSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
  dgramSocket.sendto(send_data, ("255.255.255.255", 9))

  # quit python script
  sys.exit(0)

if __name__ == '__main__':
  main()
