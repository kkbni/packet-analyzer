from dataclasses import dataclass
import socket

@dataclass
class ARPPacket:
    hw_type: int # 1 -> Ethernet
    protocol: int # 0x0800 -> IPv4
    hw_addr_len: int # len of MAC = 6
    proto_addr_len: int # len of IPv4 = 4
    operation: int # 1 -> req | 2 -> rep
    sender_hw_addr: str # sender MAC
    sender_proto_addr: str # sender IP
    target_hw_addr: str # target MAC
    target_proto_addr: str # target IP

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 28:
            raise ValueError('ARP packet: incomplete header\n')

        hw_type = int.from_bytes(data[0:2], 'big')
        protocol = int.from_bytes(data[2:4], 'big')

        # not standard ARP
        if hw_type != 1 or protocol != 0x0800:
            raise ValueError('ARP packet: not Ethernet-IPv4\n')

        hw_addr_len = data[4]

        if hw_addr_len != 6:
            raise ValueError('ARP packet: invalid MAC address length\n')

        proto_addr_len = data[5]

        if proto_addr_len != 4:
            raise ValueError('ARP packet: invalid IPv4 address length\n')

        operation = int.from_bytes(data[6:8], 'big')
        sender_mac = data[8:14].hex(':')
        sender_ip = socket.inet_ntop(socket.AF_INET, data[14:18])
        target_mac = data[18:24].hex(':')
        target_ip = socket.inet_ntop(socket.AF_INET, data[24:28])

        return cls(
            hw_type, protocol, hw_addr_len, proto_addr_len, operation,
            sender_mac, sender_ip, target_mac, target_ip
        )

    def __str__(self):
        op_map = {
            1: 'request (1)',
            2: 'reply (2)'
            }
        op = op_map.get(self.operation, 'unknown')

        return (
            f'-- ARP packet:\n'
            f'operation: {op}\n'
            f'src MAC: {self.sender_hw_addr}\n'
            f'src IP: {self.sender_proto_addr}\n'
            f'dest MAC: {self.target_hw_addr}\n'
            f'dest IP: {self.target_proto_addr}\n'
        )

    @property
    def ip_proto(self):
        return None

    @property
    def payload(self):
        return None
