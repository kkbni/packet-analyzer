from .capture import PacketCapturer
from .parsers.ethernet import EthernetFrame
from .parsers.ipv4 import IPv4Packet

ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IPV6 = 0x86DD

def main():
    print('----- Starting capture:\n')
    delim_str = '-' * 30 + '\n'

    capturer = PacketCapturer('eth0')

    for data in capturer.capture():
        print(delim_str)

        frame = EthernetFrame.parse(data)
        print(frame)

        if not frame.ether_type:
            print('IEEE 802.3 frame - skipped.\n')

        elif frame.ether_type == ETHER_TYPE_IPV4:
            try:
                print('IPv4 packet:')
                packet = IPv4Packet.parse(frame.payload)
                print(packet)
            except ValueError as err:
                print(err)

        elif frame.ether_type == ETHER_TYPE_ARP:
            print('ARP packet - Parser not implemented yet.\n')

        elif frame.ether_type == ETHER_TYPE_IPV6:
            print('IPv6 packet - Parser not implemented yet.\n')

        else:
            print(f'Uknown protocol: {frame.ether_type:#06x}.\n')


if __name__ == '__main__':
    main()