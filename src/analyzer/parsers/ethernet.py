from dataclasses import dataclass

@dataclass
class EthernetFrame:
    dest_addr: bytes
    src_addr: bytes
    type: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        # parse raw bytes and return an EthernetFrame object

        dest = data[0:6]
        src = data[6:12]
        type = int.from_bytes(data[12:14], 'big')
        payload = data[14:]

        return cls(dest, src, type, payload)

    def __str__(self):
        dest_str = self.dest_addr.hex(':')
        src_str = self.src_addr.hex(':')
        type = self.type

        return f'src: {src_str}\ndest: {dest_str}\ntype: {type:#06x}\n'