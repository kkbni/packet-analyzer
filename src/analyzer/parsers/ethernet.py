from dataclasses import dataclass

@dataclass
class EthernetFrame:
    dest_mac: str
    src_mac: str
    ether_type: int   # Network Layer Protocol
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        # parse raw bytes and return an EthernetFrame object

        dest_mac = data[0:6].hex(':')
        src_mac = data[6:12].hex(':')

        ether_type = int.from_bytes(data[12:14], 'big')

        # IEEE 802.3 frame -> ether_type is Length
        if ether_type <= 1500:
            ether_type = 0 # set to 0 to skip these frames
        # else it is the actual EtherType

        payload = data[14:]

        return cls(dest_mac, src_mac, ether_type, payload)

    def __str__(self):
        return f'src MAC: {self.src_mac}\ndest MAC: {self.dest_mac}\nprotocol: {self.ether_type:#06x}\n'