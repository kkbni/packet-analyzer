from .network import IPv4Packet, ARPPacket, IPv6Packet

# ---- PROTO CONSTANTS ----

ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IPV6 = 0x86DD

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

# ---- DISPATCH MAPS ----

PARSERS_NETWORK = {
    ETHER_TYPE_IPV4 : IPv4Packet.parse,
    ETHER_TYPE_ARP : ARPPacket.parse,
    ETHER_TYPE_IPV6 : IPv6Packet.parse
}

PARSERS_TRANSPORT = {

}

# ---- DISPATCH FUNCTIONS ----

def parse_network_layer(ether_type: int, data: bytes):

    if not ether_type:
        print('IEEE 802.3 frame - skipped\n')
        return None

    parser = PARSERS_NETWORK.get(ether_type)

    if parser:
        try:
            return parser(data)
        except ValueError as err:
            print(err)
            return None

    else:
        print(f'Uknown Network Layer protocol: {ether_type:#06x}\n')
        return None

def parse_transport_layer(ip_proto: int, data: bytes):
    pass