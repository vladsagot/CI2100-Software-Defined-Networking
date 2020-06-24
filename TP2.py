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
    1: {'10.0.1.1'},
    2: {'10.0.2.1'},
    3: {'10.0.3.1'}
}


class Router(object):

    def __init__(self, connection):
        log.debug("Router is running.")
        self.connection = connection
        connection.addListeners(self)

        self.router_mac_address = EthAddr("22:22:22:22:22:22")

        # Dictionary of { destiny IP: output PORT }
        self.ip_to_port = {}
        # arp_cache:
        # A dictionary with a host source IP and source MAC adresses (IPV4, MAC)
        self.arp_cache = {}
        # message_queue_for_ARP_reply:
        # A nested dictionary with IP destiny and IPV4 packed_in ('packet.payload.protodst|dstip', 'packet_in') types.
        # nested_dict = { 'dstipA': {1: 'packet_in1', 2: 'packet_in2'},
        #                 'dstipB': {1: 'packet_in1'}, 2: 'packet_in2'}
        self.message_queue_for_ARP_reply = {}

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
        log.debug("Send IPV4 packets in ARP waiting list to %s" % protodst)
        for packet_in_id in self.message_queue_for_ARP_reply[protodst]:
            self.resend_packet(self.message_queue_for_ARP_reply[protodst][packet_in_id], self.ip_to_port[protodst])
            #########################################
            # Check and chage for IP sender is best #
            #########################################
        del self.message_queue_for_ARP_reply[protodst]

    def had_ip_info(self, ip_address):
        return ip_address in self.arp_cache and ip_address in self.ip_to_port

    def add_ip_info(self, ip_address, mac_address, port):
        log.debug("Add: IP %s, MAC %s into arp_cache" % ip_address, mac_address)
        log.debug("Add: IP %s, PORT %s into ip_to_port" % ip_address, port)
        self.arp_cache[ip_address] = mac_address
        self.ip_to_port[ip_address] = port

    def ip_in_message_queue(self, ip_address):
        return ip_address in self.message_queue_for_ARP_reply[ip_address]

    def send_arp_reply(self, packet, packet_in):
        arp_reply = pkt.arp()
        # MAC adresses
        # ARP cache MAC
        arp_reply.hwsrc = self.arp_cache[packet.payload.protodst]
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
        ether.src = self.arp_cache[packet.payload.protodst]
        ether.payload = arp_reply
        # Router sends the ARP Reply to a host
        self.resend_packet(ether, packet_in.in_port)
        log.debug("Router send arp.REPLY: IP %s, MAC %s" % arp_reply.protodst, arp_reply.hwdst)

    def send_arp_request(self, protosrc, protodst):
        arp_request = pkt.arp()
        # MAC adresses
        # Actual router MAC
        arp_request.hwsrc = self.router_mac_address
        arp_request.hwdst = pkt.ETHER_BROADCAST
        # Creates ARP REQUEST
        arp_request.opcode = pkt.arp.REQUEST
        # IP adresses
        arp_request.protosrc = protosrc
        arp_request.protodst = protodst
        # Ethernet packet
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.ARP_TYPE
        ether.dst = pkt.ETHER_BROADCAST
        ether.src = self.router_mac_address
        ether.payload = arp_request
        # Router sends the ARP Request to a host
        self.resend_packet(ether, of.OFPP_FLOOD)
        log.debug("Router send arp.REQUEST: IP %s, MAC %s" % arp_request.protodst, arp_request.hwdst)

    # Using ARP packet payload
    # Fuente: https://noxrepo.github.io/pox-doc/html/#example-arp-messages
    def arp_inbox_handler(self, packet, packet_in):
        # Writes or rewrites the ARP cache with source IP and source MAC adresses
        # Writes or rewrites the ip_to_port with source IP and port
        if not self.had_ip_info(packet.payload.protosrc):
            self.add_ip_info(packet.payload.protosrc, packet.payload.hwsrc, packet_in.in_port)
            # The IP, MAC and PORT of input packet are know, we can clear message_queue_for_ARP_reply with this.
            if self.ip_in_message_queue(packet.payload.protosrc):
                self.arp_cache_handler(packet.payload.protosrc)

        if packet.payload.opcode == pkt.arp.REQUEST:
            # The router is consulted by a host, to obtain a MAC address of a certain IP address
            # ARP REQUEST packet
            # If the router had de MAC address, then creates ARP.REPLY
            if self.had_ip_info(packet.payload.protosrc):
                self.send_arp_reply(packet, packet_in)
            # If the router doesn't have the MAC address, ask to other hosts
            else:
                self.resend_packet(packet_in, of.OFPP_FLOOD)
        elif packet.payload.opcode == pkt.arp.REPLY:
            log.debug("Router %s receives arp.REPLY packet." % packet.payload.protodst)

    # If network is out of scope, it sends an ICMP unreachable packet
    def icmp_unreachable(self, packet, packet_in):
        log.debug("The IP %s is unreachable." % packet.payload.dstip)
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
            log.debug("Send ICMP ECHO_REPLY to IP %s" % packet.payload.dstip)
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
    def ip_is_reachable(self, ip_address):
        ip = IPAddr(ip_address)
        return (ip.inNetwork(route_table[1]['subnetIP'], 24)
                or ip.inNetwork(route_table[2]['subnetIP'], 24)
                or ip.inNetwork(route_table[3]['subnetIP'], 24))

    def ip_packet_is_from_router(self, ip_address):
        return (ip_address in default_gateway[1]
                or ip_address in default_gateway[2]
                or ip_address in default_gateway[3])

    # Using IPV4 packet payload
    def ip_inbox_handler(self, packet, packet_in):
        ip = IPAddr(packet.payload.dstip)
        # Checks if a given IP is unreachable
        if not self.ip_is_reachable(packet.payload.dstip):
            self.icmp_unreachable(packet, packet_in)
        else:
            log.debug("The IP %s is reachable." % packet.payload.dstip)
            # Checks if ICMP is for the router IP interfaces (default gateways)
            if (packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL
                    and self.ip_packet_is_from_router(packet.payload.dstip)):
                self.icmp_handler(packet, packet_in)

            # Normal IP packets can reach after this line, the router needs to verify if the IP is in his ARP cache
            elif self.had_ip_info(packet.payload.dstip):
                return
            # IP packet is not in the ARP cache
            else:
                # send_arp_request(self, protosrc, protodst, hwsrc)
                self.send_arp_request(packet.payload.srcip, packet.payload.dstip)

    def act_like_router(self, packet, packet_in):
        if packet.type == pkt.ethernet.ARP_TYPE:
            log.debug("ARP packet received from %s to %s" % packet.payload.protosrc, packet.payload.protodst)
            self.arp_inbox_handler(packet, packet_in)
        elif packet.type == pkt.ethernet.IP_TYPE:
            log.debug("IPV4 packet received from %s to %s" % packet.payload.protosrc, packet.payload.protodst)
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
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_router)
