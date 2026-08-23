from .ipv4 import IPv4Packet

ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IPV6 = 0x86DD

PARSERS_NETWORK = {
    ETHER_TYPE_IPV4 : IPv4Packet.parse
}

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
        print(f'Uknown protocol: {ether_type:#06x}\n')
        return None