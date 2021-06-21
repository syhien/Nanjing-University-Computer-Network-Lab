#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
import threading
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class ARPCachedTable(object):
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
        self.queue = []
        self.requesting = set()
        self.arptable = ARPCachedTable()
        self.table = set()

        for intf in self.net.interfaces():
            self.table.add( (intf.ipaddr, intf.netmask, IPv4Address('0.0.0.0'), intf.name) )
        table_file = open('forwarding_table.txt')
        try:
            for line in table_file:
                table_entry = line.split()
                self.table.add( (IPv4Address(table_entry[0]), IPv4Address(table_entry[1]), IPv4Address(table_entry[2]), table_entry[3]) )
        finally:
            table_file.close()

    def longest_prefix_match(self, ipaddr: switchyard.llnetbase.IPv4Address):
        log_info(f"begin match")
        match_lenth = 0
        next_hopip = IPv4Address('0.0.0.0')
        match_itface = 'None'
        for ip, netmask, hopip, itface in self.table:
            if (int(ipaddr) & int(netmask)) == (int(ip) & int(netmask)) and int(netmask) > match_lenth:
                match_lenth = int(netmask)
                match_itface = itface
                next_hopip = hopip
        log_info(next_hopip)
        log_info(match_itface)
        log_info(f"end match")
        return next_hopip, match_itface

    def send_arp_request(self, targetipaddr: switchyard.llnetbase.IPv4Address, itface, myhwaddr, myipaddr, recv):
        log_info(f"mul-sending {targetipaddr}")
        for i in range(5):
            if targetipaddr in self.requesting:
                log_info(f"mul-sengind no.{i}")
                self.net.send_packet(itface, create_ip_arp_request(myhwaddr, myipaddr, targetipaddr))
                time.sleep(1)
            else:
                return
        log_info(f"{recv} has no arp reply, del it")
        log_info(self.queue)
        log_info(recv)
        self.queue.remove(recv)
        self.requesting.remove(targetipaddr)
        log_info(self.queue)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        
        log_info(packet)

        #handle arp
        if 'Arp' in packet.headers():
            arp = packet.get_header(Arp)
            self.arptable.add(arp.senderprotoaddr, arp.senderhwaddr)
            if arp.senderprotoaddr in self.requesting:
                self.requesting.remove(arp.senderprotoaddr)
            if arp.operation == ArpOperation.Request:
                #log_info(f"ARP request received!{arp}")
                try:
                    targethwaddr = self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr
                except KeyError:
                    #log_info(f"No interface assigned to {arp.targetprotoaddr}! Ignore it")
                    return
                self.net.send_packet(ifaceName, create_ip_arp_reply(targethwaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr))
                log_info(f"Send ARP reply asking {arp.targetprotoaddr}")
            return
        
        #forward packet
        ipv4 = packet.get_header(IPv4)
        eth = packet.get_header(Ethernet)
        nexthop, match_itface = self.longest_prefix_match(ipv4.dst)
        if match_itface == 'None':
            log_info(f"remove packet {recv}")
            self.queue.remove(recv)
            return
        if str(nexthop) == '0.0.0.0':
            nexthop = ipv4.dst
        if nexthop in self.requesting:
            return            
        if self.arptable.isintable(nexthop) == False:
            log_info(f"need to arp request")
            self.requesting.add(nexthop)
            t = threading.Thread(target=self.send_arp_request, args=(nexthop, match_itface, self.net.interface_by_name(match_itface).ethaddr, self.net.interface_by_name(match_itface).ipaddr, recv, ))
            t.start()
            return
        log_info(f"begin to edit header")
        eth.src = self.net.interface_by_name(match_itface).ethaddr
        eth.dst = self.arptable.get(nexthop)
        ipv4.ttl = ipv4.ttl - 1
        del packet[IPv4]
        del packet[Ethernet]
        packet.insert_header(0, ipv4)
        packet.insert_header(0, eth)
        log_info(f"remove packet {recv}")
        self.queue.remove(recv)
        self.net.send_packet(match_itface, packet)


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

            #self.handle_packet(recv)
            if 'Arp' not in recv.packet.headers() and 'IPv4' not in recv.packet.headers():
                continue
            if 'Arp' in recv.packet.headers():
                self.handle_packet(recv)
            else:
                self.queue.append(recv)
            cur_queue = self.queue.copy()
            log_info(f"show cur_queue")
            log_info(cur_queue)
            log_info(f"end showing queue")
            for i in cur_queue:
                self.handle_packet(i)                

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
