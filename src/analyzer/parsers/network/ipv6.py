from dataclasses import dataclass
import socket

EXTENSION_HEADERS = {0, 43, 44, 50, 51, 60, 135}

@dataclass
class IPv6Packet:
    version: int # =6 -> ipv6
    traffic_class: int # ToS
    flow_label: int
    payload_len: int
    next_header: int # protocol or extension header
    hop_limit: int # TTL
    src_ip: str
    dest_ip: str
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 40:
            raise ValueError('IPv6 packet: incomplete header')

        version = data[0] >> 4
        if version != 6:
            raise ValueError(f'IPv6 packet: invalid version - {version}\n')

        traffic_class = ( int.from_bytes(data[0:2], 'big') >> 4 )& 0x00FF
        flow_label = int.from_bytes(data[1:4], 'big') & 0x0FFFFF
        
        payload_len = int.from_bytes(data[4:6], 'big')
        if 40 + payload_len > len(data):
            raise ValueError('IPv6 packet: payload is truncated')

        next_header = data[6]
        if next_header in EXTENSION_HEADERS:
            raise ValueError('IPv6 packet: extension headers included\n')

        hop_limit = data[7]

        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dest_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

        total_len = 40 + payload_len
        payload = data[40:total_len]

        return cls(version, traffic_class, flow_label, payload_len, 
                   next_header, hop_limit, src_ip, dest_ip, payload)

    def __str__(self):
        return (
            f'-- IPv6 packet:\n'
            f'src IP: {self.src_ip}\n'
            f'dest IP: {self.dest_ip}\n'
            f'protocol: {self.next_header}\n'
        )

    @property
    def ip_proto(self):
        return self.next_header