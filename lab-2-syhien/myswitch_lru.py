'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import collections
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    eth_dict = collections.OrderedDict()

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            if len(eth_dict) == 5 and eth.src not in eth_dict:
                eth_dict.popitem(last=False)
            if eth.src not in eth_dict
                eth_dict [eth.src] = fromIface
            log_info("Received a packet intended for me")
        else:
            if len(eth_dict) == 5 and eth.src not in eth_dict:
                eth_dict.popitem(last=False)
            if eth.src not in eth_dict
                eth_dict [eth.src] = fromIface
            if eth.dst not in eth_dict:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                log_info (f"Sending packet {packet} to {eth_dict[eth.dst]}")
                net.send_packet(eth_dict[eth.dst], packet)

    net.shutdown()
