from dataclasses import dataclass

@dataclass
class UDPDatagram:
    src_port: int
    dest_port: int
    length: int
    checksum: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 8:
            raise ValueError('UDP datagram: incomplete header\n')

        src_port = int.from_bytes(data[0:2], 'big')
        dest_port = int.from_bytes(data[2:4], 'big')
        length = int.from_bytes(data[4:6], 'big')
        if length < 8 or length > len(data):
            raise ValueError('UDP datagram: invalid length\n')
        checksum = int.from_bytes(data[6:8], 'big')

        payload = data[8:length]

        return cls(src_port, dest_port, length, checksum, payload)

    def __str__(self):
        return (
            f'-- UDP datagram:\n'
            f'src port: {self.src_port}\n'
            f'dest port: {self.dest_port}\n'
        )

    @property
    def application_ports(self):
        return (self.src_port, self.dest_port)