from .capture import PacketCapturer
from .parsers.dispatch import parse_link_layer, parse_network_layer, \
    parse_ip_payload, parse_application_layer

def main():
    print('----- Starting capture:\n')
    delim_str = '-' * 30 + '\n'

    capturer = PacketCapturer('eth0')

    for data in capturer.capture():
        print(delim_str)

        link_pdu = parse_link_layer(data) # Frame
        if not link_pdu: 
            continue
        print(link_pdu)
            
        network_pdu = parse_network_layer( # Packet
            link_pdu.ether_type, 
            link_pdu.payload
        )
        if not network_pdu: 
            continue
        print(network_pdu)

        if not (network_pdu.ip_proto and network_pdu.payload):
            continue
        inner_proto_pdu = parse_ip_payload(
            network_pdu.ip_proto, 
            network_pdu.payload
        )
        if not inner_proto_pdu:
            continue
        print(inner_proto_pdu)

        if not (inner_proto_pdu.application_ports and inner_proto_pdu.payload):
            continue
        application_pdu = parse_application_layer(
            inner_proto_pdu.application_ports, 
            inner_proto_pdu.payload
        )
        if not application_pdu:
            continue
        print(application_pdu)

if __name__ == '__main__':
    main()