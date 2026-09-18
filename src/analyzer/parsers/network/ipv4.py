from dataclasses import dataclass
import socket

@dataclass
class IPv4Packet:
    version: int    # =4 -> ipv4
    ihl: int    # Internet Header Len - in 32bit words
    tos: int    # Type of Service
    total_len: int
    identification: int
    flags: int
    frag_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dest_ip: str
    options: bytes
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 20:
            raise ValueError('IPv4 packet: incomplete header')

        version = data[0] >> 4
        if version != 4:
            raise ValueError('IPv4 packet: invalid version')
    
        ihl = data[0] & 0x0F
        if ihl < 5:
            raise ValueError('IPv4 packet: invalid IHL')
        
        header_len = ihl * 4
        if header_len > len(data):
            raise ValueError('IPv4 packet: header is truncated')
    
        tos = data[1]
        
        total_len = int.from_bytes(data[2:4], 'big')
        if total_len < header_len or total_len > len(data):
            raise ValueError(
                'IPv4 packet: invalid total length'
                f'(header={header_len}, total={total_len}, captured={len(data)})'
                )
        
        identification = int.from_bytes(data[4:6], 'big')
    
        flags = int.from_bytes(data[6:8], 'big') >> 13
        frag_offset = int.from_bytes(data[6:8], 'big') & 0x1FFF
    
        ttl = data[8]
        protocol = data[9]
        checksum = int.from_bytes(data[10:12], 'big')
    
        src_ip = socket.inet_ntop(socket.AF_INET, data[12:16])
        dest_ip = socket.inet_ntop(socket.AF_INET, data[16:20])
    
        # options left if IHL > 5
        options = data[20:header_len] if header_len > 20 else b''
        payload = data[header_len:total_len]

        return cls(version, ihl, tos, total_len, identification, flags, frag_offset, 
                   ttl, protocol, checksum, src_ip, dest_ip, options, payload)

    def __str__(self):
        return (
            f'-- IPv4 packet:\n'
            f'src IP: {self.src_ip}\n'
            f'dest IP: {self.dest_ip}\n'
            f'protocol: {self.protocol}\n'
        )

    @property
    def ip_proto(self):
        return self.protocol