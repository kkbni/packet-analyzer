from .capture import PacketCapturer
from .parsers.link import EthernetFrame
from .parsers.dispatch import parse_network_layer, parse_ip_payload, parse_application_layer

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
                inner_proto_pdu = parse_ip_payload(network_pdu.ip_proto, network_pdu.payload)

                if inner_proto_pdu:
                    print(inner_proto_pdu)

                    if inner_proto_pdu.application_ports and inner_proto_pdu.payload:
                        application_pdu = parse_application_layer(inner_proto_pdu.application_ports, inner_proto_pdu.payload)

                        if application_pdu:
                            print(application_pdu)

if __name__ == '__main__':
    main()