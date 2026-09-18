from .link import EthernetFrame
from .network import IPv4Packet, ARPPacket, IPv6Packet, ICMPv4Message, ICMPv6Message
from .transport import TCPSegment, UDPDatagram
from .application import DNSMessage, HTTPMessage, TLSMessage

# ---- PROTO CONSTANTS ----

ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IPV6 = 0x86DD

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMPV4 = 1
IP_PROTO_ICMPV6 =  58

APP_PORT_DNS = 53
APP_PORT_HTTP = 80
APP_PORT_HTTPS = 443

# ---- DISPATCH MAPS ----

PARSERS_NETWORK = {
    ETHER_TYPE_IPV4: IPv4Packet.parse,
    ETHER_TYPE_ARP: ARPPacket.parse,
    ETHER_TYPE_IPV6: IPv6Packet.parse
}

PARSERS_IP_PAYLOAD = {
    IP_PROTO_TCP: TCPSegment.parse,
    IP_PROTO_UDP: UDPDatagram.parse,
    IP_PROTO_ICMPV4: ICMPv4Message.parse,
    IP_PROTO_ICMPV6: ICMPv6Message.parse
}

PARSERS_APPLICATION = {
    APP_PORT_DNS: DNSMessage.parse,
    APP_PORT_HTTP: HTTPMessage.parse,
    APP_PORT_HTTPS: TLSMessage.parse
}

# ---- HELPER CLASS ----

class CorruptedLayer:
    # dummy PDU with exception data

    def __init__(self, error: Exception | str):
        self.error = error

    def __str__(self):
        return (
            f'--- CORRUPTED LAYER:\n'
            f'{self.error}\n'
            )

# ---- DISPATCH FUNCTIONS ----

def parse_link_layer(data: bytes):

    parser = EthernetFrame.parse

    try:
        return parser(data)
    except Exception as err:
        return CorruptedLayer(err)

def parse_network_layer(ether_type: int, data: bytes):

    if not ether_type:
        return CorruptedLayer('IEEE 802.3 frame - skipped')

    parser = PARSERS_NETWORK.get(ether_type)

    if parser:
        try:
            return parser(data)
        except Exception as err:
            return CorruptedLayer(err)

    else:
        return CorruptedLayer(f'Unknown Network Layer protocol: {ether_type:#06x}')

def parse_ip_payload(ip_proto: int, data: bytes):

    parser = PARSERS_IP_PAYLOAD.get(ip_proto)

    if parser:
        try:
            return parser(data)
        except Exception as err:
            return CorruptedLayer(err)

    else:
        return CorruptedLayer(f'Unknown protocol in IP payload: {ip_proto}')

def parse_application_layer(ports: tuple[int, int], data: bytes):
    src_port, dest_port = ports

    parser = PARSERS_APPLICATION.get(src_port) or PARSERS_APPLICATION.get(dest_port)

    if parser:
        try:
            return parser(data)
        except Exception as err:
            return CorruptedLayer(err)

    return None