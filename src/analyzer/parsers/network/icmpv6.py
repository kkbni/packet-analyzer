from dataclasses import dataclass

@dataclass
class ICMPv6Message:
    type: int
    code: int
    checksum: int
    identifier: int # for type 128 / 129
    seq_num: int # for type 128 / 129
    extended_header: bytes # else
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        type = data[0]
        code = data[1]
        checksum = int.from_bytes(data[2:4], 'big')

        identifier = 0
        seq_num = 0
        extended_header = b''

        if type in (128, 129):
            identifier = int.from_bytes(data[4:6], 'big')
            seq_num = int.from_bytes(data[6:8], 'big')
        else:
            extended_header = data[4:8]

        payload = data[8:]

        return cls(type, code, checksum, identifier, seq_num, extended_header, payload)

    def __str__(self):
        type_map = {
            1: 'Destination Unreachable',
            2: 'Packet Too Big',
            3: 'Time Exceeded',
            4: 'Parameter Problem',
            128: 'Echo Request',
            129: 'Echo Reply',
            130: 'Multicast Listener Query',
            131: 'Multicast Listener Report',
            132: ' Multicast Listener Done',
            133: 'Router Solicitation',
            134: 'Router Advertisement',
            135: 'Neighbor Solicitation',
            136: 'Neighbor Advertisement',
            137: 'Redirect'
        }

        type_str = type_map.get(self.type, 'Uknown')

        if self.type in (128, 129):
            info_str = (
                f'identifier: {self.identifier}\n'
                f'sequence number: {self.seq_num}\n'
                )
        else:
            info_str = f'header data: {self.extended_header.hex()}\n'

        return (
            f'-- ICMPv6 message:\n'
            f'type: ({self.type}) {type_str}\n'
            f'{info_str}'
        )
