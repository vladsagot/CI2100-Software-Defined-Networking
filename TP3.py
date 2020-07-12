import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

route_table = {
    1: {'subnet': '10.0.1.0/24',
        'subnetIP': '10.0.1.0',
        'interfaceName': 's1-eth1'},
    2: {'subnet': '10.0.2.0/24',
        'subnetIP': '10.0.2.0',
        'interfaceName': 's1-eth2'},
    3: {'subnet': '10.0.3.0/24',
        'subnetIP': '10.0.3.0',
        'interfaceName': 's1-eth3'}
}

default_gateway = {
    1: '10.0.1.1',
    2: '10.0.2.1',
    3: '10.0.3.1'
}


class Packet:
    def __init__(self, packet, packet_in):
        self.packet = packet
        self.packet_in = packet_in


class Router(object):

    def __init__(self, connection):
        log.debug("Router is running.")
        self.connection = connection
        connection.addListeners(self)

        self.router_mac_address = EthAddr("22:22:22:22:22:22")

        # Dictionary of { destiny IP: output PORT }
        self.ip_to_port = {default_gateway[1]: 1,
                           default_gateway[2]: 3,
                           default_gateway[3]: 2,
                           "10.0.3.90": 2}
        # arp_cache:
        # A dictionary with a host source IP and source MAC adresses (IPV4, MAC)
        self.arp_cache = {default_gateway[1]: str(self.router_mac_address),
                          default_gateway[2]: str(self.router_mac_address),
                          default_gateway[3]: str(self.router_mac_address),
                          "10.0.3.90": str(self.router_mac_address)}
        # message_queue_for_ARP_reply:
        # A nested dictionary with IP destiny and IPV4 packed_in ('packet.payload.protodst|dstip', 'packet_in') types.
        # nested_dict = { 'dstipA': {1: 'packet_in1', 2: 'packet_in2'},
        #                 'dstipB': {1: 'packet_in1'}, 2: 'packet_in2'}
        self.message_queue_for_ARP_reply = {}
        # Dictionary of { source IP: { source output TCP PORT: PAT output TCP port }
        self.tcp_ports_to_subnet_3 = {}

    def print_arp_cache(self):
        for i in self.arp_cache:
            print("ARP CACHE | IP: " + str(i) + " MAC: " + str(self.arp_cache[i]))

    def resend_packet(self, packet, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    # NEED: Install flow where this put packets in waiting list
    # Cleans cache sending packets that have a valid source IP in ARP cache.
    # Takes the MAC address from the ARP cache.
    # message_queue_for_ARP_reply:
    # A dictionary with IP destiny and IPV4 packed_in ('packet.payload.protodst|dstip', 'packet_in') types.
    def arp_cache_handler(self, protodst):
        protodst = str(protodst)
        log.debug("ARP CACHE HANDLER: Send IPV4 packets in ARP waiting list to %s" % (str(protodst)))
        for packet_id in self.message_queue_for_ARP_reply[protodst]:
            log.debug("packet_in_id %s" % str(packet_id))
            self.send_ip_packet(self.message_queue_for_ARP_reply[protodst][packet_id], protodst)
        del self.message_queue_for_ARP_reply[protodst]

    def had_ip_info(self, ip_address):
        ip_address = str(ip_address)
        return ip_address in self.arp_cache and ip_address in self.ip_to_port

    def add_ip_info(self, ip_address, mac_address, port):
        ip_address = str(ip_address)
        mac_address = str(mac_address)
        port = int(port)
        log.debug("Add: IP %s, MAC %s into arp_cache" % (str(ip_address), str(mac_address)))
        log.debug("Add: IP %s, PORT %s into ip_to_port" % (str(ip_address), str(port)))
        self.arp_cache[ip_address] = mac_address
        self.ip_to_port[ip_address] = port

    # If IP had messages in queue, then return True
    def ip_in_message_queue(self, ip_address):
        ip_address = str(ip_address)
        return ip_address in self.message_queue_for_ARP_reply

    def send_arp_reply(self, packet, packet_in):
        arp_reply = pkt.arp()
        # MAC adresses
        # ARP cache MAC
        arp_reply.hwsrc = EthAddr(self.arp_cache[str(packet.payload.protodst)])
        arp_reply.hwdst = packet.payload.hwsrc
        # Creates ARP REPLY
        arp_reply.opcode = pkt.arp.REPLY
        # IP adresses
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc
        # Ethernet packet
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.ARP_TYPE
        ether.dst = packet.src
        ether.src = EthAddr(self.arp_cache[str(packet.payload.protodst)])
        ether.payload = arp_reply
        # Router sends the ARP Reply to a host
        self.resend_packet(ether, packet_in.in_port)

    @staticmethod
    def get_default_gateway_from_ip(ip_address):
        ip = str(ip_address)
        ip = IPAddr(ip)
        for i in route_table:
            if ip.inNetwork(IPAddr(route_table[i]['subnetIP']), 24):
                return default_gateway[i]

    def send_arp_request(self, protodst):
        protodst = str(protodst)
        arp_request = pkt.arp()
        # MAC adresses
        # Actual router MAC
        arp_request.hwsrc = EthAddr(self.router_mac_address)
        arp_request.hwdst = pkt.ETHER_BROADCAST
        # Creates ARP REQUEST
        arp_request.opcode = pkt.arp.REQUEST
        # IP adresses
        arp_request.protosrc = IPAddr(self.get_default_gateway_from_ip(protodst))
        log.debug("get_default_gateway_from_ip: IP %s -> GATEWAY %s" % (
            str(protodst), str(self.get_default_gateway_from_ip(protodst))))
        arp_request.protodst = IPAddr(protodst)
        # Ethernet packet
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.ARP_TYPE
        ether.dst = pkt.ETHER_BROADCAST
        ether.src = EthAddr(self.router_mac_address)
        ether.payload = arp_request
        # Router sends the ARP Request to a host
        self.resend_packet(ether, of.ofp_port_rev_map['OFPP_FLOOD'])
        log.debug("Router send arp.REQUEST: IP %s, MAC %s" % (str(arp_request.protodst), str(arp_request.hwdst)))

    # Using ARP packet payload
    # Fuente: https://noxrepo.github.io/pox-doc/html/#example-arp-messages
    def arp_inbox_handler(self, packet, packet_in):
        # Writes or rewrites the ARP cache with source IP and source MAC adresses
        # Writes or rewrites the ip_to_port with source IP and port
        if not self.had_ip_info(str(packet.payload.protosrc)):
            self.add_ip_info(str(packet.payload.protosrc), str(packet.payload.hwsrc), packet_in.in_port)
            # The IP, MAC and PORT of input packet are know, we can clear message_queue_for_ARP_reply with this.
            if self.ip_in_message_queue(str(packet.payload.protosrc)):
                self.arp_cache_handler(str(packet.payload.protosrc))

        if packet.payload.opcode == pkt.arp.REQUEST:
            # The router is consulted by a host, to obtain a MAC address of a certain IP address
            # ARP REQUEST packet
            # If the router had the MAC address, then creates ARP.REPLY
            if self.had_ip_info(str(packet.payload.protodst)):
                self.send_arp_reply(packet, packet_in)
            # If the router doesn't have the MAC address, ask to other hosts
            else:
                self.resend_packet(packet_in, of.ofp_port_rev_map['OFPP_FLOOD'])
        elif packet.payload.opcode == pkt.arp.REPLY:
            log.debug("Router %s receives arp.REPLY packet." % (str(packet.payload.protodst)))

    # If network is out of scope, it sends an ICMP unreachable packet
    def icmp_unreachable(self, packet, packet_in):
        log.debug("The IP %s is unreachable." % (str(packet.payload.dstip)))
        ip_packet = packet.payload

        unreach_packet = pkt.unreach()
        unreach_packet.payload = ip_packet

        icmp_reply = pkt.icmp()
        icmp_reply.type = pkt.TYPE_DEST_UNREACH
        icmp_reply.payload = unreach_packet

        ipv4_reply = pkt.ipv4()
        ipv4_reply.srcip = ip_packet.dstip
        ipv4_reply.dstip = ip_packet.srcip
        ipv4_reply.protocol = pkt.ipv4.ICMP_PROTOCOL
        ipv4_reply.payload = icmp_reply

        eth_reply = pkt.ethernet()
        eth_reply.type = pkt.ethernet.IP_TYPE
        eth_reply.src = packet.dst
        eth_reply.dst = packet.src
        eth_reply.payload = ipv4_reply

        self.resend_packet(eth_reply, packet_in.in_port)

    # If the ICMP ECHO_REQUEST packet is for the router, creates an ECHO_REPLY
    def icmp_handler(self, packet, packet_in):
        ip_packet = packet.payload
        icmp_packet = ip_packet.payload
        if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
            log.debug("Send ICMP ECHO_REPLY to IP %s" % (str(packet.payload.dstip)))
            icmp_reply = pkt.icmp()
            icmp_reply.type = pkt.TYPE_ECHO_REPLY
            icmp_reply.payload = icmp_packet.payload

            ipv4_reply = pkt.ipv4()
            ipv4_reply.srcip = ip_packet.dstip
            ipv4_reply.dstip = ip_packet.srcip
            ipv4_reply.protocol = pkt.ipv4.ICMP_PROTOCOL
            ipv4_reply.payload = icmp_reply

            eth_reply = pkt.ethernet()
            eth_reply.type = pkt.ethernet.IP_TYPE
            eth_reply.src = packet.dst
            eth_reply.dst = packet.src
            eth_reply.payload = ipv4_reply
            self.resend_packet(eth_reply, packet_in.in_port)

    # Checks if a given IP is reachable in the given scenario
    @staticmethod
    def ip_is_reachable(ip_address):
        ip_address = str(ip_address)
        ip = IPAddr(ip_address)
        return ((ip.inNetwork(IPAddr(route_table[1]['subnetIP']), 24))
                or (ip.inNetwork(IPAddr(route_table[2]['subnetIP']), 24))
                or (ip.inNetwork(IPAddr(route_table[3]['subnetIP']), 24)))

    @staticmethod
    def ip_packet_is_from_router(ip_address):
        ip_address = str(ip_address)
        return (ip_address in default_gateway[1]
                or ip_address in default_gateway[2]
                or ip_address in default_gateway[3])

    # Get a new TCP source port to send a packet to subnet 3
    def get_tcp_port_to_subnet_3_num(self):
        count = 0
        for ip in self.tcp_ports_to_subnet_3:
            count += len(self.tcp_ports_to_subnet_3[ip])
        return 2000 + count

    # Returns an assigned TCP port from source IP
    def get_tcp_port_to_subnet_3(self, srcip, srctpcport):
        srcip = str(srcip)
        srctpcport = int(srctpcport)
        if srcip not in self.tcp_ports_to_subnet_3:
            self.tcp_ports_to_subnet_3[srcip] = {}
            self.tcp_ports_to_subnet_3[srcip][srctpcport] = self.get_tcp_port_to_subnet_3_num()
        elif srctpcport not in self.tcp_ports_to_subnet_3[srcip]:
            self.tcp_ports_to_subnet_3[srcip][srctpcport] = self.get_tcp_port_to_subnet_3_num()
        log.debug("----- tcp_ports_to_subnet_3[%s][%s] = %s" % (
            str(srcip), str(srctpcport), str(self.tcp_ports_to_subnet_3[srcip][srctpcport])))
        return self.tcp_ports_to_subnet_3[srcip][srctpcport]

    def get_associated_info_to_tcp_port_from_subnet_3(self, dsttcpport):
        dsttcpport = int(dsttcpport)
        ip_associated = "0.0.0.0"
        tcp_port_associated = 0
        for ip in self.tcp_ports_to_subnet_3:
            for tcpport in self.tcp_ports_to_subnet_3[ip]:
                if self.tcp_ports_to_subnet_3[ip][tcpport] == dsttcpport:
                    ip_associated = ip
                    tcp_port_associated = tcpport
        return ip_associated, tcp_port_associated

    # Resolve PAT to a packet from subnet 3
    def send_tcp_ip_packet_from_subnet_3(self, packet_object, dstip):
        packet = packet_object.packet
        packet_in = packet_object.packet_in
        dsttcpport = int(packet.payload.payload.dstport)
        dstip, dsttcpport = self.get_associated_info_to_tcp_port_from_subnet_3(dsttcpport)

        packet.payload.payload.dstport = int(dsttcpport)
        packet.payload.dstip = IPAddr(dstip)
        packet.src = EthAddr(self.router_mac_address)
        packet.dst = EthAddr(self.arp_cache[dstip])
        log.debug(
            "\n\nSEND FROM H3:\n" + str(packet) + "\n" + str(packet.payload) + "\n" + str(
                packet.payload.payload) + "\n")
        self.resend_packet(packet, self.ip_to_port[dstip])

    # Apply PAT (Port Address Translation)
    def send_tcp_ip_packet_to_subnet_3(self, packet_object, dstip):
        packet = packet_object.packet
        packet_in = packet_object.packet_in
        dstip = str(dstip)
        srcip = str(packet.payload.srcip)
        srctpcport = str(packet.payload.payload.srcport)

        packet.payload.payload.srcport = self.get_tcp_port_to_subnet_3(srcip, srctpcport)
        packet.payload.srcip = IPAddr("10.0.3.90")
        packet.src = EthAddr(self.router_mac_address)
        packet.dst = EthAddr(self.arp_cache[dstip])
        log.debug(
            "\n\nSEND TO H3:\n" + str(packet) + "\n" + str(packet.payload) + "\n" + str(packet.payload.payload) + "\n")
        self.resend_packet(packet, self.ip_to_port[dstip])

    @staticmethod
    def is_to_subnet(dstip, subnet):
        dstip = str(dstip)
        subnet = int(subnet)
        return dstip != "10.0.3.90" and IPAddr(dstip).inNetwork(IPAddr(route_table[subnet]['subnetIP']), 24)

    @staticmethod
    def is_from_subnet(srcip, subnet):
        srcip = str(srcip)
        subnet = int(subnet)
        return IPAddr(srcip).inNetwork(IPAddr(route_table[subnet]['subnetIP']), 24)

    # Fuente: https://noxrepo.github.io/pox-doc/html/#set-ethernet-source-or-destination-address
    # https://noxrepo.github.io/pox-doc/html/#example-installing-a-table-entry
    # https://openflow.stanford.edu/display/ONL/POX+Wiki.html
    def send_ip_packet(self, packet_object, dstip):
        packet = packet_object.packet
        packet_in = packet_object.packet_in

        # Checks if is a TCP packet to H3 to apply PAT (Port Address Translation)
        if packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL and self.is_to_subnet(packet.payload.dstip, 3):
            log.debug("----- Send packet to H3 %s from %s" % (str(packet.payload.dstip), str(packet.payload.srcip)))
            self.send_tcp_ip_packet_to_subnet_3(packet_object, dstip)
        # Checks if is a TCP packet from H3
        elif packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL and self.is_from_subnet(packet.payload.srcip, 3):
            log.debug("----- Receive packet from H3 %s to %s" % (str(packet.payload.srcip), str(packet.payload.dstip)))
            self.send_tcp_ip_packet_from_subnet_3(packet_object, dstip)
        else:
            dstip = str(dstip)
            packet.scr = EthAddr(self.router_mac_address)
            packet.dst = EthAddr(self.arp_cache[dstip])
            self.resend_packet(packet, self.ip_to_port[dstip])

            # Install flow
            # msg = of.ofp_flow_mod()
            # msg.data = packet_in
            # msg.match.dl_type = pkt.ethernet.IP_TYPE
            # msg.match.nw_dst = IPAddr(dstip)
            # msg.actions.append(of.ofp_action_dl_addr.set_src(packet.src))
            # msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.dst))
            # msg.actions.append(of.ofp_action_output(port=self.ip_to_port[dstip]))
            # self.connection.send(msg)

    # Firewall
    def ip_inbox_firewall(self, packet, packet_in):
        return

    # Using IPV4 packet payload
    def ip_inbox_handler(self, packet, packet_in):
        self.ip_inbox_firewall(packet, packet_in)
        # Checks if a given IP is unreachable
        if not self.ip_is_reachable(str(packet.payload.dstip)):
            self.icmp_unreachable(packet, packet_in)
        else:
            log.debug("The IP %s is reachable." % (str(packet.payload.dstip)))
            # Checks if ICMP is for the router IP interfaces (default gateways)
            if (packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL
                    and self.ip_packet_is_from_router(str(packet.payload.dstip))):
                self.icmp_handler(packet, packet_in)

            # Normal IP packets can reach after this line, the router needs to verify if the IP is in his ARP cache
            elif self.had_ip_info(str(packet.payload.dstip)):
                self.send_ip_packet(Packet(packet, packet_in), str(packet.payload.dstip))
            # IP packet is not in the ARP cache
            else:
                # message_queue_for_ARP_reply:
                # A nested dictionary with IP destiny and IPV4 packed_in
                # ('packet.payload.protodst|dstip', 'packet_in') types.
                # nested_dict = { 'dstipA': {1: 'packet_in1', 2: 'packet_in2'},
                #                 'dstipB': {1: 'packet_in1'}, 2: 'packet_in2'}
                # Creates nested dictionary for message queue
                if str(packet.payload.dstip) not in self.message_queue_for_ARP_reply:
                    self.message_queue_for_ARP_reply[str(packet.payload.dstip)] = {}
                len_message_queque_ip = len(self.message_queue_for_ARP_reply[str(packet.payload.dstip)])
                self.message_queue_for_ARP_reply[str(packet.payload.dstip)][len_message_queque_ip] = Packet(packet,
                                                                                                            packet_in)
                log.debug(
                    "Add to message queue: IP %s POS %s" % (str(packet.payload.dstip), str(len_message_queque_ip)))
                # Send ARP request to obtain MAC address of the destiny IP
                self.send_arp_request(str(packet.payload.dstip))

    def act_like_router(self, packet, packet_in):
        if packet.type == pkt.ethernet.ARP_TYPE:
            log.debug(
                "ARP packet received from %s to %s" % (str(packet.payload.protosrc), str(packet.payload.protodst)))
            self.arp_inbox_handler(packet, packet_in)
        elif packet.type == pkt.ethernet.IP_TYPE:
            log.debug(
                "IPV4 packet received from %s to %s" % (str(packet.payload.srcip), str(packet.payload.dstip)))
            self.ip_inbox_handler(packet, packet_in)

    def _handle_PacketIn(self, event):
        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        packet_in = event.ofp  # The actual ofp_packet_in message.
        self.act_like_router(packet, packet_in)


def launch():
    def start_router(event):
        log.debug("Controlling %s" % (str(event.connection, )))
        Router(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_router)
