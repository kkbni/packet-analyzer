from .capture import PacketCapturer
from .parsers.link import EthernetFrame
from .parsers.dispatch import parse_network_layer, parse_transport_layer

def main():
    print('----- Starting capture:\n')
    delim_str = '-' * 30 + '\n'

    capturer = PacketCapturer('eth0')

    for data in capturer.capture():
        print(delim_str)

        link_pdu = EthernetFrame.parse(data) # Frame
        print(link_pdu)
        
        network_pdu = parse_network_layer(link_pdu.ether_type, link_pdu.payload) # Packet
        if network_pdu:
            print(network_pdu)

            if network_pdu.ip_proto and network_pdu.payload:
                transport_pdu = parse_transport_layer(network_pdu.ip_proto, network_pdu.payload)

                if transport_pdu:
                    print(transport_pdu)

if __name__ == '__main__':
    main()