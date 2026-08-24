from dataclasses import dataclass

@dataclass
class UDPSegment:
    src_port: int
    dest_port: int
    length: int
    checksum: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        src_port = int.from_bytes(data[0:2], 'big')
        dest_port = int.from_bytes(data[2:4], 'big')
        length = int.from_bytes(data[4:6], 'big')
        checksum = int.from_bytes(data[6:8], 'big')

        payload = data[8:length]

        return cls(src_port, dest_port, length, checksum, payload)

    def __str__(self):
        return (
            f'-- UDP segment:\n'
            f'src port: {self.src_port}\n'
            f'dest port: {self.dest_port}\n'
        )