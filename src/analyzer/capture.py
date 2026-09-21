import socket
import queue

from .parsers.dispatch import CorruptedLayer, \
    parse_link_layer, parse_network_layer, \
    parse_ip_payload, parse_application_layer

ETH_P_ALL = 0x0003 # proto for every packet
MAX_IPV4_PACKET_SIZE = 65535

class PacketCapturer:
    def __init__(self, interface: str):
        self.interface = interface

        self.socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(ETH_P_ALL)
        )

        self.socket.bind((interface, 0))

    def capture(self):
        while True:
            data, _ = self.socket.recvfrom(MAX_IPV4_PACKET_SIZE)
            yield data

def assemble_packet(link_pdu=None, net_pdu=None, inner_pdu=None, app_pdu=None):
    return (link_pdu, net_pdu, inner_pdu, app_pdu)

def capture_worker(
        capturer: PacketCapturer, 
        packet_history: dict, 
        packet_queue: queue.Queue
):
    packet_id = 0

    for data in capturer.capture():
        packet_id += 1

        # parse the packet
        link_pdu = parse_link_layer(data)
        if isinstance(link_pdu, CorruptedLayer):
            packet_history[packet_id] = assemble_packet(link_pdu)
            packet_queue.put(packet_id)
            continue

        network_pdu = parse_network_layer(
            link_pdu.ether_type, 
            link_pdu.payload
        )
        if isinstance(network_pdu, CorruptedLayer):
            packet_history[packet_id] = assemble_packet(link_pdu, network_pdu)
            packet_queue.put(packet_id)
            continue

        inner_proto_pdu = None
        if network_pdu.ip_proto and network_pdu.payload:
            inner_proto_pdu = parse_ip_payload(
                network_pdu.ip_proto, 
                network_pdu.payload
            )
        if isinstance(inner_proto_pdu, CorruptedLayer):
            packet_history[packet_id] = assemble_packet(link_pdu, network_pdu, inner_proto_pdu)
            packet_queue.put(packet_id)
            continue

        application_pdu = None
        if inner_proto_pdu and inner_proto_pdu.application_ports and inner_proto_pdu.payload:
            application_pdu = parse_application_layer(
                inner_proto_pdu.application_ports, 
                inner_proto_pdu.payload
            )
        packet_history[packet_id] = assemble_packet(link_pdu, network_pdu, inner_proto_pdu, application_pdu)
        packet_queue.put(packet_id)