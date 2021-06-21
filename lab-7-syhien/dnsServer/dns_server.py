'''DNS Server for Content Delivery Network (CDN)
'''

import random
import sys
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math

import re
from collections import namedtuple


__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        DNS_record = namedtuple('DNS_record', ['domain', 'recordtype', 'values'])
        r_file = open(dns_file)
        try:
            for line in r_file:
                record_entry = line.split()
                self._dns_table.append(DNS_record(record_entry[0], record_entry[1], tuple(record_entry[2:])))
        finally:
            r_file.close()

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        ...

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        for i in self.table:
            if i.domain[0] == '*':
                #self.log_info("[-a-zA-Z0-9]"+i.domain)
                if re.match("[-a-zA-Z0-9]"+i.domain, request_domain_name + '.', re.I):
                    response_type = i.recordtype
                    response_val = i.values
                    break
            else:
                if re.match(i.domain, request_domain_name + '.', re.I):
                    response_type = i.recordtype
                    response_val = i.values
                    break
        if response_type == "A":
            if len(response_val) != 1:
                client_pos = IP_Utils.getIpLocation(client_ip)
                if client_pos != (None,None):
                    minRecord = 0
                    minDistance = (client_pos[0]-IP_Utils.getIpLocation(response_val[0])[0])**2 + (client_pos[1]-IP_Utils.getIpLocation(response_val[0])[1])**2
                    for i in range(1, len(response_val)):
                        if (client_pos[0]-IP_Utils.getIpLocation(response_val[i])[0])**2 + (client_pos[1]-IP_Utils.getIpLocation(response_val[i])[1])**2 < minDistance:
                            minRecord = i
                            minDistance = (client_pos[0]-IP_Utils.getIpLocation(response_val[i])[0])**2 + (client_pos[1]-IP_Utils.getIpLocation(response_val[i])[1])**2
                    response_val = response_val[minRecord]
                else:
                    response_val = response_val[random.randint(0, len(response_val))]
            else:
                response_val = response_val[0]
        elif response_type == "CNAME":
            response_val = response_val[0]
        # -------------------------------------------------
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
