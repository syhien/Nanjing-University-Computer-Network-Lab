#!/usr/bin/env python3

import copy
import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp = "192.168.100.1",
            num = "39"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterip = IPv4Address(blasterIp)
        self.num = int(num)
        self.recvCount = int(0)
        self.recvPacket = set()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        if packet.has_header(Ethernet) == False or packet.has_header(IPv4) == False or packet.has_header(UDP) == False:
            return
        del packet[Ethernet]
        del packet[IPv4]
        del packet[UDP]
        p = Packet()
        eth = Ethernet()
        eth.ethertype = EtherType.IPv4
        eth.src = '20:00:00:00:00:01'
        eth.dst = '40:00:00:00:00:02'
        p += eth
        ipv4 = IPv4()
        ipv4.src = '192.168.200.1'
        ipv4.dst = self.blasterip
        ipv4.protocol = IPProtocol.UDP
        ipv4.ttl = 2
        p += ipv4
        p += UDP()
        log_info(f"num is {int.from_bytes(packet[0].to_bytes()[:4], 'big')}")
        if int.from_bytes(packet[0].to_bytes()[:4], 'big') not in self.recvPacket:
            self.recvCount += 1
            self.recvPacket.add(int.from_bytes(packet[0].to_bytes()[:4], 'big'))
        seqpl = RawPacketContents(packet[0].to_bytes()[:4] + (packet[0].to_bytes()[6:] + bytes(8))[:8])
        p += seqpl
        #log_info(f"{p}")
        self.net.send_packet(fromIface, p)
        if self.recvCount == self.num:
            self.shutdown()

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
