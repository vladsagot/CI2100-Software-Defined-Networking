import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

route_table = {
    1: {'subnet': '10.0.1.100/24',
        'subnetIP': '10.0.1.100',
        'interfaceName': 's1-eth1',
        'interfaceIP': '10.0.1.1',
        'switchPort': 1},
    2: {'subnet': '10.0.2.100/24',
        'subnetIP': '10.0.2.100',
        'interfaceName': 's1-eth2',
        'interfaceIP': '10.0.2.1',
        'switchPort': 3},
    3: {'subnet': '10.0.3.100/24',
        'subnetIP': '10.0.3.100',
        'interfaceName': 's1-eth3',
        'interfaceIP': '10.0.3.1',
        'switchPort': 2}
}

default_gateway = {
    1: '10.0.1.1',
    2: '10.0.2.1',
    3: '10.0.3.1'
}


class Router(object):

    def __init__(self, connection):
        log.debug("Router is running.")
        self.connection = connection
        connection.addListeners(self)

        self.router_mac_address = EthAddr("22:22:22:22:22:22")

        # Dictionary of { destiny IP: output PORT }
        self.ip_to_port = {default_gateway[1]: 1,
                           default_gateway[2]: 2,
                           default_gateway[3]: 3}
        # arp_cache:
        # A dictionary with a host source IP and source MAC adresses (IPV4, MAC)
        self.arp_cache = {default_gateway[1]: str(self.router_mac_address),
                          default_gateway[2]: str(self.router_mac_address),
                          default_gateway[3]: str(self.router_mac_address)}
        # message_queue_for_ARP_reply:
        # A nested dictionary with IP destiny and IPV4 packed_in ('packet.payload.protodst|dstip', 'packet_in') types.
        # nested_dict = { 'dstipA': {1: 'packet_in1', 2: 'packet_in2'},
        #                 'dstipB': {1: 'packet_in1'}, 2: 'packet_in2'}
        self.message_queue_for_ARP_reply = {}

    def print_arp_cache(self):
        for i in self.arp_cache:
            print("ARP CACHE | IP: " + str(i) + " MAC: " + str(self.arp_cache[i]))

    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
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
        log.debug("Send IPV4 packets in ARP waiting list to %s" % (str(protodst)))
        for packet_in_id in self.message_queue_for_ARP_reply[protodst]:
            log.debug("packet_in_id %s" % str(packet_in_id))
            self.send_ip_packet(self.message_queue_for_ARP_reply[protodst][packet_in_id], protodst)
            #########################################
            # Check and chage for IP sender is best #
            #########################################
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
        ether.dst = packet.payload.hwsrc
        ether.src = EthAddr(self.arp_cache[str(packet.payload.protodst)])
        ether.payload = arp_reply
        # Router sends the ARP Reply to a host
        self.resend_packet(ether, packet_in.in_port)
        log.debug("Router send arp.REPLY: TO | IP %s, MAC %s " % (str(arp_reply.protodst), str(ether.dst)))

    def send_arp_request(self, protosrc, protodst):
        protosrc = str(protosrc)
        protodst = str(protodst)
        arp_request = pkt.arp()
        # MAC adresses
        # Actual router MAC
        arp_request.hwsrc = EthAddr(self.router_mac_address)
        arp_request.hwdst = pkt.ETHER_BROADCAST
        # Creates ARP REQUEST
        arp_request.opcode = pkt.arp.REQUEST
        # IP adresses
        arp_request.protosrc = IPAddr(protosrc)
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
        icmp_packet = ip_packet.payload
        icmp_reply = pkt.icmp()
        icmp_reply.code = pkt.CODE_UNREACH_NET
        icmp_reply.type = pkt.TYPE_DEST_UNREACH
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
        return (IPAddr(ip.inNetwork(route_table[1]['subnetIP']), 24)
                or IPAddr(ip.inNetwork(route_table[2]['subnetIP']), 24)
                or IPAddr(ip.inNetwork(route_table[3]['subnetIP']), 24))

    @staticmethod
    def ip_packet_is_from_router(ip_address):
        ip_address = str(ip_address)
        return (ip_address in default_gateway[1]
                or ip_address in default_gateway[2]
                or ip_address in default_gateway[3])

    # Fuente: https://noxrepo.github.io/pox-doc/html/#set-ethernet-source-or-destination-address
    # https://noxrepo.github.io/pox-doc/html/#example-installing-a-table-entry
    # https://openflow.stanford.edu/display/ONL/POX+Wiki.html
    def send_ip_packet(self, packet_in, dstip):
        dstip = str(dstip)
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action_outport = of.ofp_action_output(port=self.ip_to_port[dstip])
        msg.actions.append(action_outport)
        action_hwdst = of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_cache[dstip]))
        msg.actions.append(action_hwdst)
        self.connection.send(msg)
        log.debug("SEND: IP packet to %s, PORT %s" % (str(dstip), str(self.ip_to_port[dstip])))
        #################
        # Installs flow #
        #################
        msg = of.ofp_flow_mod()
        # Match destiny IP and packet IP type
        msg.match.nw_dst = IPAddr(dstip)
        msg.match.dl_type = 0x800  # dl_type = 0x800 (IPv4)
        # Generate same route created before and adds to flowtable
        action_outport = of.ofp_action_output(port=self.ip_to_port[dstip])
        msg.actions.append(action_outport)
        action_hwdst = of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_cache[dstip]))
        msg.actions.append(action_hwdst)
        self.connection.send(msg)

    # Using IPV4 packet payload
    def ip_inbox_handler(self, packet, packet_in):
        # Checks if a given IP is unreachable
        if not self.ip_is_reachable(packet.payload.dstip):
            self.icmp_unreachable(packet, packet_in)
        else:
            log.debug("The IP %s is reachable." % (str(packet.payload.dstip)))
            # Checks if ICMP is for the router IP interfaces (default gateways)
            if (packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL
                    and self.ip_packet_is_from_router(packet.payload.dstip)):
                self.icmp_handler(packet, packet_in)

            # Normal IP packets can reach after this line, the router needs to verify if the IP is in his ARP cache
            elif self.had_ip_info(packet.payload.dstip):
                self.send_ip_packet(packet_in, packet.payload.dstip)
            # IP packet is not in the ARP cache
            else:
                # message_queue_for_ARP_reply:
                # A nested dictionary with IP destiny and IPV4 packed_in
                # ('packet.payload.protodst|dstip', 'packet_in') types.
                # nested_dict = { 'dstipA': {1: 'packet_in1', 2: 'packet_in2'},
                #                 'dstipB': {1: 'packet_in1'}, 2: 'packet_in2'}
                # Creates nested dictionary for message queue
                if packet.payload.dstip not in self.message_queue_for_ARP_reply:
                    self.message_queue_for_ARP_reply[str(packet.payload.dstip)] = {}
                len_message_queque_ip = len(self.message_queue_for_ARP_reply[str(packet.payload.dstip)])
                self.message_queue_for_ARP_reply[str(packet.payload.dstip)][len_message_queque_ip] = packet_in
                log.debug(
                    "Add to massage queue: IP %s POS %s" % (str(packet.payload.dstip), str(len_message_queque_ip)))
                # Send ARP request to obtain MAC address of the destiny IP
                self.send_arp_request(packet.payload.srcip, packet.payload.dstip)

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
