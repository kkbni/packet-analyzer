import socket

ETH_P_ALL = 0x0003 # proto for every packet

class PacketCapturer:
    def __init__(self, interface : str):
        self.interface = interface

        self.socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(ETH_P_ALL)
        )

        self.socket.bind((interface, 0))

    def capture(self):
        while True:
            data, addr = self.socket.recvfrom(1024)
            yield data