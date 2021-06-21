#!/usr/bin/env python3

import time
from random import randint, random
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp = "192.168.200.1",
            num = "39",
            length="100",
            senderWindow="5",
            timeout="3000",
            recvTimeout="1000"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeip = blasteeIp
        self.num = int(num)
        self.pllength = int(length)
        self.sw = int(senderWindow)
        self.timeout = float(int(timeout) / 1000)
        self.recvtimeout = float(int(recvTimeout) / 1000)
        self.startTime = 0
        self.ackNum = 0
        self.ack = set()
        self.lhs = 0
        self.rhs = 0
        self.timer = time.time()
        self.sendCount = {}
        self.toCount = 0
        self.sendbytesCount = 0
        self.pl = {}
        self.sendnext = True

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        if packet.has_header(Ethernet) == False or packet.has_header(IPv4) == False or packet.has_header(UDP) == False:
            return
        del packet[0]
        del packet[0]
        del packet[0]
        recvACK = int.from_bytes(packet[0].to_bytes()[:4], 'big')
        if recvACK not in self.ack:
            self.ack.add(recvACK)
            self.ackNum += 1
        log_info(f"received ACK No.{recvACK}")
        if self.ackNum == self.num:
            self.shutdown(printInfo=True)
        if self.lhs in self.ack:
            self.sendnext = True

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        log_info(f"no pkg, lhs is {self.lhs}, rhs is {self.rhs}")

        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        pkt[0].dst = '40:00:00:00:00:01'
        pkt[0].ethertype = EtherType.IPv4
        pkt[0].src = '10:00:00:00:00:01'
        pkt[1].src = '192.168.100.1'
        pkt[1].protocol = IPProtocol.UDP
        pkt[1].dst = '192.168.200.1'

        # Do other things here and send packet
        while self.lhs in self.ack:
            self.lhs += 1
        self.rhs = min(self.num, self.lhs + self.sw - 1)
        log_info(f"ackNum = {self.ackNum}")
        if self.ackNum == self.num:
            self.shutdown(printInfo=True)
        for i in range(self.lhs, self.rhs + 1):
            if i in self.ack:
                continue
            if i not in self.sendCount:
                self.sendCount[i] = 1
            else:
                self.sendCount[i] += 1
            if i not in self.pl.keys():
                pl = randint(0, pow(2, self.pllength * 8) - 1)
                self.pl[i] = pl
            seqlenpl = RawPacketContents(i.to_bytes(4, 'big') + self.pllength.to_bytes(2, 'big') + self.pl[i].to_bytes(self.pllength, 'big'))
            self.sendbytesCount += self.pllength
            self.net.send_packet(self.net.interfaces()[0].name, pkt + seqlenpl)
            log_info(f"send packet No.{int.from_bytes(seqlenpl.to_bytes()[:4], 'big')} {pkt + seqlenpl}")
            break

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        self.startTime = time.time()
        self.lhs = 1
        self.rhs = 1
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvtimeout)
            except NoPackets:
                if self.sendnext:
                    self.timer = time.time()
                    self.handle_no_packet()
                    self.sendnext = False
                elif (time.time() - self.timer) > self.timeout:
                    self.toCount += 1
                    self.timer = time.time()
                    self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self, printInfo = False):
        self.net.shutdown()
        if printInfo == False:
            return
        endTime = time.time()
        log_info(f"Total TX time: {int(endTime - self.startTime)}")
        retxcnt = 0
        for i in self.sendCount.values():
            retxcnt += i - 1
        log_info(f"Number of reTX: {retxcnt}")
        log_info(f"Number of coarse TOs: {self.toCount}")
        log_info(f"Throughput: {float(self.sendbytesCount) / (endTime - self.startTime)}")
        log_info(f"Goodput: {float(self.pllength * self.num) / (endTime - self.startTime)}")


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
