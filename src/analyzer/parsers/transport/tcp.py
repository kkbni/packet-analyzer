from dataclasses import dataclass

@dataclass
class TCPSegment:
    src_port: int
    dest_port: int
    seq_num: int
    ack_num: int
    data_offset: int # header len in 32-bit words
    # ---- flags ----
    flag_urg: bool # urgent
    flag_ack: bool # acknowledgement
    flag_psh: bool # push
    flag_rst: bool # reset
    flag_syn: bool # synchronize
    flag_fin: bool # finish
    # --------------
    window_size: int
    checksum: int
    urgent_ptr: int # used if flag_urg
    options: bytes
    payload: bytes

    def _get_flags_str(self):
        flags = []
        if self.flag_urg: flags.append('URG')
        if self.flag_ack: flags.append('ACK')
        if self.flag_psh: flags.append('PSH')
        if self.flag_rst: flags.append('RST')
        if self.flag_syn: flags.append('SYN')
        if self.flag_fin: flags.append('FIN')

        flags_str = ', '.join(flags) if flags else '-'
        return flags_str

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 20:
            raise ValueError('TCP segment: incomplete header')

        src_port = int.from_bytes(data[0:2], 'big')
        dest_port = int.from_bytes(data[2:4], 'big')
        seq_num = int.from_bytes(data[4:8], 'big')
        ack_num = int.from_bytes(data[8:12], 'big')
        data_offset = ( data[12] >> 4 ) & 0x0F

        flags = data[13]
        flag_fin = ( flags & 1 ) != 0
        flag_syn = ( ( flags >> 1 ) & 1 ) != 0
        flag_rst = ( ( flags >> 2 ) & 1 ) != 0
        flag_psh = ( ( flags >> 3 ) & 1 ) != 0
        flag_ack = ( ( flags >> 4 ) & 1 ) != 0
        flag_urg = ( ( flags >> 5 ) & 1 ) != 0

        window_size = int.from_bytes(data[14:16], 'big')
        checksum = int.from_bytes(data[16:18], 'big')
        urgent_ptr = int.from_bytes(data[18:20], 'big')

        header_len = data_offset * 4
        if data_offset < 5 or header_len > len(data):
            raise ValueError('TCP segment: invalid data offset')
        options = data[20:header_len] if header_len > 20 else b''

        payload = data[header_len:]

        return cls(src_port, dest_port, seq_num, ack_num, data_offset,
                   flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, 
                   window_size, checksum, urgent_ptr, options, payload)

    def __str__(self):
        flags_str = self._get_flags_str()
        return (
            f'-- TCP segment:\n'
            f'src port: {self.src_port}\n'
            f'dest port: {self.dest_port}\n'
            f'seq number: {self.seq_num}\n'
            f'flags: {flags_str}\n'
        )

    def info(self):
        flags_str = self._get_flags_str()
        return f'ports: {self.src_port} -> {self.dest_port}, seq: {self.seq_num}, flags: {flags_str}'

    @property
    def application_ports(self):
        return (self.src_port, self.dest_port)
