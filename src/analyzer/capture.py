import socket

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