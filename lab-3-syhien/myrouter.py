#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class CachedTable(object):
    def __init__(self):
        self.__table = {}

    def isintable(self, ipaddr):
        for i, j in self.__table.items():
            if i == ipaddr:
                if time.time() - j[1] > 10:
                    del self.__table[i]
                    return False
                else:
                    return True
        return False
    
    def add(self, ipaddr, macaddr):
        self.__table[ipaddr] = (macaddr, time.time())

    def get(self, ipaddr):
        return self.__table[ipaddr][0]

    def print(self):
        log_info(f"{self.__table}")

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.table = CachedTable()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        if 'Arp' not in packet.headers():
            log_info(f"No ARP header! Ignore it")
            return
        else:
            arp = packet.get_header(Arp)
        
        self.table.add(arp.senderprotoaddr, arp.senderhwaddr)

        try:
            targethwaddr = self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr
        except KeyError:
            log_info(f"No interface assigned to {arp.targetprotoaddr}! Ignore it")
            return
        
        self.net.send_packet(ifaceName, create_ip_arp_reply(targethwaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr))
        log_info(f"Send ARP reply asking {arp.targetprotoaddr}")

    def start(self):
        '''A running daemon of the router.
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
            self.table.print()

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
