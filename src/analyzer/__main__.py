from .capture import PacketCapturer
from .parsers.link import EthernetFrame
from .parsers.dispatch import parse_network_layer, parse_transport_layer

def main():
    print('----- Starting capture:\n')
    delim_str = '-' * 30 + '\n'

    capturer = PacketCapturer('eth0')

    for data in capturer.capture():
        print(delim_str)

        frame = EthernetFrame.parse(data)
        print(frame)

        packet = parse_network_layer(frame.ether_type, frame.payload)
        if packet:
            print(packet)

            if packet.ip_proto and packet.payload:
                segment = parse_transport_layer(packet.ip_proto, packet.payload)

                if segment:
                    print(segment)

if __name__ == '__main__':
    main()