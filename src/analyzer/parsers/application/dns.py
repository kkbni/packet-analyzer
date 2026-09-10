from dataclasses import dataclass
import socket

@dataclass
class ResourceRecord:
    name: str
    record_type: int
    record_class: int
    ttl: int
    data_len: int
    data: str

    @classmethod
    def parse(cls, data: bytes, offset: int, parse_func) -> tuple['ResourceRecord', int]: # -> (ResourceRecord, offset)
        name, offset = parse_func(data, offset)
        if len(data[offset:]) < 10:
            raise ValueError('DNS recourse record: incomplete header\n')

        record_type = int.from_bytes(data[ offset : offset + 2], 'big')
        offset += 2
        record_class = int.from_bytes(data[ offset : offset + 2], 'big')
        offset += 2
        ttl = int.from_bytes(data[ offset : offset + 4], 'big')
        offset += 4
        data_len = int.from_bytes(data[ offset : offset + 2], 'big')
        offset += 2

        if data_len > len(data) - offset:
            raise ValueError('DNS resource record: data is truncated\n')

        data_bytes = data[ offset : offset + data_len ]

        if record_type == 1: # A record (IPv4)
            if data_len != 4:
                raise ValueError('DNS resource record: invalid A record length\n')
            interpreted_data = socket.inet_ntop(socket.AF_INET, data_bytes)

        elif record_type == 5: # Canonical DNS Name (CNAME)
            interpreted_data, name_end = parse_func(data, offset)
            if name_end > offset + data_len:
                raise ValueError('DNS resource record: CNAME data is truncated\n')
            
        elif record_type == 28: # AAAA record (IPv6)
            if data_len != 16:
                raise ValueError('DNS resource record: invalid AAAA record length\n')
            interpreted_data = socket.inet_ntop(socket.AF_INET6, data_bytes)

        else:
            interpreted_data = f'<Raw>: {data_bytes.hex()}'

        offset += data_len
        record = cls(name, record_type, record_class, ttl, data_len, interpreted_data)

        return record, offset

    def __str__(self):
        type_map = {
            1: 'A',
            5: 'CNAME',
            28: 'AAAA',
            41: 'OPT'
        }
        type_str = type_map.get(self.record_type, f'Unknown: {self.record_type}')

        name = self.name if self.name else '<Root>'
        return f'{name} ({type_str}): {self.data}'

@dataclass
class DNSMessage:
    identification: int
    # ---- flags ----
    flag_qr: bool # 0 -> req | 1 -> res
    opcode: int # type of query
    flag_aa: bool # authoritative answer
    flag_tc: bool # truncation
    flag_rd: bool # recursion desired
    flag_ra: bool # recursion available
    rcode: int # response code
    # --------------
    qdcount: int # num of questions
    # RRs - resource records
    ancount: int # num of answer RRs
    nscount: int # num of authority RRs
    arcount: int # num of additional RRs

    queries: list[str]
    answer_rrs: list[ResourceRecord]
    authority_rrs: list[ResourceRecord]
    additional_rrs: list[ResourceRecord]

    @classmethod
    # A helper to parse DNS names and names through compression pointers in the header
    def _parse_name(cls, data: bytes, start_offset: int) -> tuple[str, int]: # -> (name, start_offset)
        if start_offset >= len(data):
            raise ValueError('DNS name: offset is outside packet\n')

        parts = [] # parts of the domain name
        cur_offset = start_offset
        # cur_offset -> used offset for current reading
        # start_offset -> returned offset for the next reading
        jumped = False # if a pointer was used
        visited_offsets = set() # to check for pointer loops

        while True:
            if cur_offset >= len(data):
                raise ValueError('DNS name: data is truncated\n')
            if cur_offset in visited_offsets:
                raise ValueError('DNS name: compression pointer loop\n')
            visited_offsets.add(cur_offset)

            part_len = data[cur_offset]

            if part_len == 0:
                if not jumped: # advance only if we haven't followed a ptr yet
                    start_offset += 1
                break

            if ( part_len & 0xC0 ) == 0xC0: # if first two bits are '11' it's a 2-byte ptr
                if cur_offset + 1 >= len(data):
                    raise ValueError('DNS name: compression pointer is truncated\n')

                if not jumped: # advance the start_offset only after the original ptr
                    start_offset += 2

                cur_offset = int.from_bytes(data[ cur_offset : cur_offset + 2 ], 'big') & 0x3FFF
                if cur_offset >= len(data):
                    raise ValueError('DNS name: compression pointer is outside packet\n')
                jumped = True

            elif part_len & 0xC0:
                raise ValueError('DNS name: invalid label length\n')

            else:
                cur_offset += 1 # skip the part_len byte
                if cur_offset + part_len > len(data):
                    raise ValueError('DNS name: label is truncated\n')

                try:
                    part = data[ cur_offset : cur_offset + part_len ].decode('utf-8')
                except UnicodeDecodeError as err:
                    raise ValueError('DNS name: invalid encoding\n') from err
                parts.append(part)

                cur_offset += part_len # skip the part

                if not jumped: # change the start for the future reading if we haven't followed a ptr
                    start_offset = cur_offset

        name = '.'.join( map(str, parts) )

        return name, start_offset

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 12:
            raise ValueError('DNS message: incomplete header\n')

        identification = int.from_bytes(data[0:2], 'big')
        flags = int.from_bytes(data[2:4], 'big')

        flag_qr = ( flags >> 15 ) != 0
        opcode = ( flags >> 11 ) & 0xF
        flag_aa = ( ( flags >> 10 ) & 0x1 ) != 0
        flag_tc = ( ( flags >> 9 ) & 0x1 ) != 0
        flag_rd = ( ( flags >> 8 ) & 0x1 ) != 0
        flag_ra = ( ( flags >> 7 ) & 0x1 ) != 0
        rcode = flags & 0xF

        qdcount = int.from_bytes(data[4:6], 'big')
        ancount = int.from_bytes(data[6:8], 'big')
        nscount = int.from_bytes(data[8:10], 'big')
        arcount = int.from_bytes(data[10:12], 'big')

        offset = 12

        queries = []
        for _ in range(qdcount):
            name, offset = cls._parse_name(data, offset)
            queries.append(name)

            if len(data[offset:]) < 4:
                raise ValueError('DNS question: incomplete data\n')

            # skip q_type (2 bytes)
            # skip q_class (2 bytes)
            offset += 4

        answer_rrs = []
        for _ in range(ancount):
            record, offset = ResourceRecord.parse(data, offset, cls._parse_name)
            answer_rrs.append(record)

        authority_rrs = []
        for _ in range(nscount):
            record, offset = ResourceRecord.parse(data, offset, cls._parse_name)
            authority_rrs.append(record)

        additional_rrs = []
        for _ in range(arcount):
            record, offset = ResourceRecord.parse(data, offset, cls._parse_name)
            additional_rrs.append(record)

        return cls(identification, 
                   flag_qr, opcode, flag_aa, flag_tc, flag_rd, flag_ra, rcode, 
                   qdcount, ancount, nscount, arcount, 
                   queries, answer_rrs, authority_rrs, additional_rrs)

    def __str__(self):
        queries_str = ', '.join(self.queries) if self.queries else 'None'
        message_type = 'response (1)' if self.flag_qr else 'request (0)'

        output_str = (
            f'-- DNS {message_type}:\n'
            f'ID: {self.identification}\n'
            f'- queries:\n' 
            f'{queries_str}\n'
            )

        if self.flag_qr: # response
            if self.answer_rrs:
                output_str += f'- answers:\n'

                for record in self.answer_rrs:
                    output_str += f'{record}\n'

            if self.authority_rrs:
                output_str += f'- authoritative answers:\n'

                for record in self.authority_rrs:
                    output_str += f'{record}\n'

            if self.additional_rrs:
                output_str += f'- additional answers:\n'

                for record in self.additional_rrs:
                    output_str += f'{record}\n'

        return output_str