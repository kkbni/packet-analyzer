from dataclasses import dataclass

@dataclass
class ICMPv4Message:
    type: int
    code: int
    checksum: int
    identifier: int # for type 0 / 8
    seq_num: int # for type 0 / 8
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

        if type in (0, 8):
            identifier = int.from_bytes(data[4:6], 'big')
            seq_num = int.from_bytes(data[6:8], 'big')
        else:
            extended_header = data[4:8]

        payload = data[8:]

        return cls(type, code, checksum, identifier, seq_num, extended_header, payload)

    def __str__(self):
        type_map = {
            0:  'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect Message',
            8: 'Echo Request',
            9: 'Router Advertisement',
            10: 'Router Solicitation',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp',
            14: 'Timestamp Reply'
        }

        type_str = type_map.get(self.type, 'Uknown')

        if self.type in (0, 8):
            info_str = (
                f'identifier: {self.identifier}\n'
                f'sequence number: {self.seq_num}\n'
                )
        else:
            info_str = f'header data: {self.extended_header.hex()}\n'

        return (
            f'-- ICMPv4 message:\n'
            f'type: ({self.type}) {type_str}\n'
            f'{info_str}'
        )
