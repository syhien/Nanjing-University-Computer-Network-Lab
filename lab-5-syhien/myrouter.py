#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

from struct import pack
import copy
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

    def ICMP_arp_request(self, targetip, itface):
        log_info(f"Arp request for ICMP error")
        self.requesting.add(targetip)
        for i in range(5):
            if targetip in self.requesting:
                log_info(f"mul-sengind no.{i}")
                self.net.send_packet(itface, create_ip_arp_request(self.net.interface_by_name(itface).ethaddr, self.net.interface_by_name(itface).ipaddr, targetip))
                time.sleep(1)
            else:
                return True
        self.requesting.remove(targetip)
        return False

    def send_arp_request(self, targetipaddr: switchyard.llnetbase.IPv4Address, itface, myhwaddr, myipaddr, recv, error_receiver = 'None'):
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
        if error_receiver != 'None':
            log_info(f"arp failed and need to icmp error")
            timestamp, ifaceName, packet = recv
            ipv4 = IPv4()
            ipv4.ttl = 64
            ipv4.protocol = IPProtocol.ICMP
            ipv4.dst = error_receiver
            nexthop, match_itface = self.longest_prefix_match(ipv4.dst)
            if str(nexthop) == '0.0.0.0':
                nexthop = ipv4.dst
            if match_itface == 'None':
                log_info(f"unable to echo reply or ICMP error, just give up")
                self.queue.remove(recv)
                self.requesting.remove(targetipaddr)
                return
            ipv4.src = self.net.interface_by_name(match_itface).ipaddr
            if self.arptable.isintable(ipv4.dst) == False and self.ICMP_arp_request(ipv4.dst, match_itface) == False:
                log_info(f"unable to echo reply or ICMP error, just give up")
                self.queue.remove(recv)
                self.requesting.remove(targetipaddr)
                return
            eth = Ethernet()
            eth.dst = self.arptable.get(ipv4.dst)
            eth.src = self.net.interface_by_name(match_itface).ethaddr
            eth.ethertype = EtherType.IPv4
            del packet[Ethernet]
            icmp = ICMP()
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = 1
            icmp.icmpdata.data = packet.to_bytes()[:28]
            p = Packet()
            p.insert_header(0, icmp)
            p.insert_header(0, ipv4)
            p.insert_header(0, eth)
            self.net.send_packet(match_itface, p)

        self.queue.remove(recv)
        self.requesting.remove(targetipaddr)
        #log_info(self.queue)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = copy.deepcopy(recv)
        
        #log_info(packet)

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
        
        if 'IPv4' not in packet.headers():
            self.queue.remove(recv)
            return
        itface = 'None'
        for intf in self.net.interfaces():
            if intf.ipaddr == packet.get_header(IPv4).dst:
                itface = intf.name
        #handle error packet, dst == myIP but isn't ICMP echo request
        if itface != 'None' and ('ICMP' not in packet.headers() or packet.get_header(ICMP).icmptype != ICMPType.EchoRequest):
            icmp = ICMP()
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = 3
            old_packet = copy.deepcopy(recv[2])
            del old_packet[Ethernet]
            icmp.icmpdata.data = old_packet.to_bytes()[:28]
            ipv4 = IPv4()
            ipv4.protocol = IPProtocol.ICMP
            ipv4.ttl = 64
            ipv4.dst = packet.get_header(IPv4).src
            nexthop, match_itface = self.longest_prefix_match(ipv4.dst)
            if match_itface == 'None':
                self.queue.remove(recv)
                return
            if str(nexthop) == '0.0.0.0':
                nexthop = ipv4.dst
            ipv4.src = self.net.interface_by_name(match_itface).ipaddr
            eth = Ethernet()
            eth.src = self.net.interface_by_name(match_itface).ethaddr
            eth.ethertype = EtherType.IPv4
            if nexthop in self.requesting:
                return
            if self.arptable.isintable(nexthop) == False:
                log_info(f"need to arp request")
                self.requesting.add(nexthop)
                t = threading.Thread(target=self.send_arp_request, args=(nexthop, match_itface, self.net.interface_by_name(match_itface).ethaddr, self.net.interface_by_name(match_itface).ipaddr, recv, ))
                t.start()
                return
            eth.dst = self.arptable.get(nexthop)
            p = Packet()
            p.insert_header(0, icmp)
            p.insert_header(0, ipv4)
            p.insert_header(0, eth)
            self.net.send_packet(ifaceName, p)
            self.queue.remove(recv)
            return

        #handle ICMP echo request(dst == myIP)
        if 'ICMP' in packet.headers() and packet.get_header(ICMP).icmptype == ICMPType.EchoRequest and itface != 'None':
            icmp = ICMP()
            icmp.icmptype = ICMPType.EchoReply
            icmp.icmpdata.sequence = packet.get_header(ICMP).icmpdata.sequence
            icmp.icmpdata.identifier = packet.get_header(ICMP).icmpdata.identifier
            icmp.icmpdata.data = packet.get_header(ICMP).icmpdata.data
            ipv4 = IPv4()
            ipv4.protocol = IPProtocol.ICMP
            ipv4.ttl = 64
            ipv4.dst = packet.get_header(IPv4).src
            ipv4.src = packet.get_header(IPv4).dst
            eth = Ethernet()
            eth.ethertype = EtherType.IPv4
            nexthop, match_itface = self.longest_prefix_match(ipv4.dst)
            if match_itface == 'None':
                log_info(f"match nothing! network unreachable")
                ipv4 = IPv4()
                ipv4.protocol = IPProtocol.ICMP
                ipv4.ttl = 64
                ipv4.dst = packet.get_header(IPv4).src
                ipv4.src = self.net.interface_by_name(ifaceName).ipaddr
                icmp = ICMP()
                icmp.icmptype = ICMPType.DestinationUnreachable
                icmp.icmpcode = 0
                eth = Ethernet()
                eth.src = packet.get_header(Ethernet).dst
                nexthop = packet.get_header(IPv4).src
                if nexthop in self.requesting:
                    return            
                if self.arptable.isintable(nexthop) == False:
                    log_info(f"need to arp request")
                    self.requesting.add(nexthop)
                    t = threading.Thread(target=self.send_arp_request, args=(nexthop, match_itface, self.net.interface_by_name(match_itface).ethaddr, self.net.interface_by_name(match_itface).ipaddr, recv, ))
                    t.start()
                    return
                eth.dst = self.arptable.get(nexthop)
                eth.ethertype = EtherType.IPv4
                old_packet = copy.deepcopy(recv[2])
                del old_packet[Ethernet]
                icmp.icmpdata.data = old_packet.to_bytes()[:28]
                p = Packet()
                p.insert_header(0, icmp)
                p.insert_header(0, ipv4)
                p.insert_header(0, eth)
                self.net.send_packet(ifaceName, p)
                self.queue.remove(recv)
                return
            if str(nexthop) == '0.0.0.0':
                nexthop = ipv4.dst
            if packet.get_header(IPv4).src in self.requesting:
                return
            if self.arptable.isintable(nexthop) == False:
                log_info(f"need to arp request")
                self.requesting.add(nexthop)
                t = threading.Thread(target=self.send_arp_request, args=(nexthop, match_itface, self.net.interface_by_name(match_itface).ethaddr, self.net.interface_by_name(match_itface).ipaddr, recv, ))
                t.start()
                return
            eth.dst = self.arptable.get(nexthop)
            eth.src = self.net.interface_by_name(match_itface).ethaddr
            p = Packet()
            p.insert_header(0, icmp)
            p.insert_header(0, ipv4)
            p.insert_header(0, eth)
            self.net.send_packet(match_itface, p)
            self.queue.remove(recv)
            return

        #forward packet
        #log_info(f"forwarding {packet}")
        ipv4 = packet.get_header(IPv4)
        log_info(f"show ipv4 :{ipv4} {ipv4.ttl}")
        eth = packet.get_header(Ethernet)
        packetdead = False
        if ipv4.ttl == 1 or ipv4.ttl == 0:
            log_info(f"ttl = 0")
            packetdead = True
            ipv4.dst = ipv4.src
        nexthop, match_itface = self.longest_prefix_match(ipv4.dst)
        if match_itface == 'None':
            log_info(f"match nothing! netword unreachable")
            ipv4 = IPv4()
            ipv4.protocol = IPProtocol.ICMP
            ipv4.ttl = 64
            ipv4.dst = packet.get_header(IPv4).src
            ipv4.src = self.net.interface_by_name(ifaceName).ipaddr
            icmp = ICMP()
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = 0
            eth = Ethernet()
            eth.src = packet.get_header(Ethernet).dst
            nexthop = packet.get_header(IPv4).src
            if nexthop in self.requesting:
                return            
            if self.arptable.isintable(nexthop) == False:
                log_info(f"need to arp request")
                self.requesting.add(nexthop)
                t = threading.Thread(target=self.send_arp_request, args=(nexthop, match_itface, self.net.interface_by_name(match_itface).ethaddr, self.net.interface_by_name(match_itface).ipaddr, recv, ))
                t.start()
                return
            eth.dst = self.arptable.get(nexthop)
            eth.ethertype = EtherType.IPv4
            old_packet = copy.deepcopy(recv[2])
            del old_packet[Ethernet]
            icmp.icmpdata.data = old_packet.to_bytes()[:28]
            p = Packet()
            p.insert_header(0, icmp)
            p.insert_header(0, ipv4)
            p.insert_header(0, eth)
            self.net.send_packet(ifaceName, p)
            self.queue.remove(recv)
            return
        if str(nexthop) == '0.0.0.0':
            nexthop = ipv4.dst
        if nexthop in self.requesting:
            return            
        if self.arptable.isintable(nexthop) == False:
            log_info(f"need to arp request")
            self.requesting.add(nexthop)
            t = threading.Thread(target=self.send_arp_request, args=(nexthop, match_itface, self.net.interface_by_name(match_itface).ethaddr, self.net.interface_by_name(match_itface).ipaddr, recv, ipv4.src))
            t.start()
            return
        if packetdead == True:
            old_packet = copy.deepcopy(recv[2])
            del old_packet[Ethernet]
            log_info(f"{old_packet}")
            ipv4.protocol = IPProtocol.ICMP
            ipv4.src = self.net.interface_by_name(match_itface).ipaddr
            ipv4.ttl = 64
            icmp = ICMP()
            icmp.icmptype = ICMPType.TimeExceeded
            icmp.icmpdata.data = old_packet.to_bytes()[:28]
            eth.src = self.net.interface_by_name(match_itface).ethaddr
            eth.dst = self.arptable.get(nexthop)
            p = Packet()
            p.insert_header(0, icmp)
            p.insert_header(0, ipv4)
            p.insert_header(0, eth)
            log_info(f"show dead packet's error ICMP:{p}")
            self.net.send_packet(match_itface, p)
            self.queue.remove(recv)
            return
        log_info(f"begin to edit packet")
        ipv4.ttl = ipv4.ttl - 1
        eth.src = self.net.interface_by_name(match_itface).ethaddr
        eth.dst = self.arptable.get(nexthop)
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
            #if 'Arp' not in recv.packet.headers() and 'IPv4' not in recv.packet.headers() and 'ICMP' not in recv.packet.headers():
            #    continue
            if 'Arp' in recv.packet.headers():
                self.handle_packet(recv)
            else:
                self.queue.append(recv)
            cur_queue = self.queue.copy()
            #log_info(f"show cur_queue")
            #log_info(cur_queue)
            #log_info(f"end showing queue")
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
