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
        self.mac_to_port = {}

        self.arp_cache = {}
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
    # A dictionary with IP destiny and packed_in ('packet.payload.protodst', 'packet_in') types.
    def arp_cache_handler(self, protodst):
        log.debug("Send ARP packets in waiting list.")
        for packet_in in self.message_queue_for_ARP_reply[protodst]:
            self.resend_packet(packet_in, self.ip_to_port[protodst])
            #########################################
            # Check and chage for IP sender is best #
            #########################################
        del self.message_queue_for_ARP_reply[protodst]

    # Fuente: https://noxrepo.github.io/pox-doc/html/#example-arp-messages
    def arp_inbox_handler(self, packet, packet_in):
        # Writes or rewrites the ARP cache with source IP and source MAC adresses
        if packet.payload.hwsrc not in self.arp_cache[packet.payload.protosrc]:
            self.arp_cache[packet.payload.protosrc] = packet.payload.hwsrc
            log.debug("Add: IP %s, MAC %s into arp_cache" % packet.payload.protosrc, packet.payload.hwsrc)
            # The IP and MAC adresses of input packet are know, we can clear ARP cache with this.
            if packet.payload.protosrc in self.message_queue_for_ARP_reply[packet.payload.protosrc]:
                log.debug("Send packets outside arp_cache: IP %s, MAC %s" % packet.payload.protosrc,
                          packet.payload.hwsrc)
                self.arp_cache_handler(packet.payload.protosrc)

        if packet.payload.opcode == pkt.arp.REQUEST:
            # The router is consulted by a host, to obtain a MAC address of a certain IP address.
            # ARP REQUEST packet
            arp_reply = pkt.arp()
            # MAC adresses
            # Actual router MAC
            arp_reply.hwsrc = self.router_mac_address
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
            ether.src = self.router_mac_address
            ether.payload = arp_reply
            # Router sends the ARP Replay to a host
            self.resend_packet(ether, packet_in.in_port)
            log.debug("Router send arp.REPLY: IP %s, MAC %s" % arp_reply.protodst, arp_reply.hwdst)
        elif packet.payload.opcode == pkt.arp.REPLY:
            ##################
            # Check if works #
            ##################
            log.debug("Router %s receives arp.REPLY packet." % packet.payload.protodst)

    def ip_inbox_handler(self, packet, packet_in):
        ip = IPAddr(packet.payload.protodst)
        # Checks if a given IP is unreachable
        if not (ip.inNetwork(route_table[1]['subnetIP'], 24)
                or ip.inNetwork(route_table[2]['subnetIP'], 24)
                or ip.inNetwork(route_table[3]['subnetIP'], 24)):
            log.debug("The IP %s is unreachable." % packet.payload.protodst)
        else:
            log.debug("The IP %s is reachable." % packet.payload.protodst)

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
