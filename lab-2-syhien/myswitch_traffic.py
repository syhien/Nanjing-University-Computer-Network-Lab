'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import random
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    eth_dict = {}

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
            if eth.src not in eth_dict:
                if len(eth_dict) == 5:
                    tmpk = random.choice(list(eth_dict.keys()))
                    for k, v in eth_dict.items():
                        if v[1] < eth_dict[tmpk][1]:
                            tmpk = k
                    del eth_dict[tmpk]
                eth_dict[eth.src] = [fromIface, 0]
            log_info("Received a packet intended for me")
        else:
            if eth.src not in eth_dict:
                if len(eth_dict) == 5:
                    tmpk = random.choice(list(eth_dict.keys()))
                    for k, v in eth_dict.items():
                        if v[1] < eth_dict[tmpk][1]:
                            tmpk = k
                    del eth_dict[tmpk]
                eth_dict[eth.src] = [fromIface, 0]
            if eth.dst not in eth_dict:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                log_info (f"Sending packet {packet} to {eth_dict[eth.dst][0]}")
                eth_dict[eth.dst][1] += 1
                net.send_packet(eth_dict[eth.dst][0], packet)

    net.shutdown()