from dataclasses import dataclass

@dataclass
class TLSMessage:
    # ---- Record header ---- 
    content_type: int
    version: int
    payload_length: int
    # ---- Handshake header ----
    handshake_type: int | None = None
    handshake_length: int | None = None
    # --------------------------
    sni: str | None = None # Server Name Identification

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 5: 
            raise ValueError('TLS message: incomplete record header')

        content_type = data[0]
        version = int.from_bytes(data[1:3], 'big')
        payload_length = int.from_bytes(data[3:5], 'big')

        if content_type != 22: # not a handshake
            # data is encrypted
            return cls(content_type, version, payload_length)

        if len(data) < 9:
            raise ValueError('TLS message: incomplete handshake header')

        handshake_type = data[5]
        handshake_len = int.from_bytes(data[6:9], 'big')
        sni_str = None

        if handshake_type == 1: # Client Hello -> can find SNI
            try:
                # start at byte 9
                # skip Client Version -> 2 bytes
                # skip Random -> 32 bytes
                offset = 9 + 2 + 32
                
                session_id_len = data[offset]
                # skip Session ID len -> 1 byte
                # skip Session ID -> session_id_len bytes
                offset += 1 + session_id_len
                
                cipher_suites_len = int.from_bytes(data[offset : offset + 2], 'big')
                # skip Cipher Suites len -> 2 bytes
                # skip Cipher Suites -> cipher_suites_len bytes
                offset += 2 + cipher_suites_len
                
                comp_methods_len = data[offset]
                # skip Compression Methods len -> 1 byte
                # skip Compression Methods -> comp_methods_len bytes
                offset += 1 + comp_methods_len
                
                extensions_len = int.from_bytes(data[offset : offset + 2], 'big')
                # skip Extensions len -> 2 bytes
                offset += 2
                
                extentions_end = offset + extensions_len
                
                while offset + 4 <= extentions_end and offset + 4 <= len(data):

                    ext_type = int.from_bytes(data[offset : offset + 2], 'big')
                    ext_len = int.from_bytes(data[offset + 2 : offset + 4], 'big')
                    # skip ext type and len
                    offset += 4
                    
                    if ext_type == 0:  # SNI ext
                        # skip List len -> 2 bytes
                        # skip Name Type -> 1 byte
                        offset += 3

                        name_len = int.from_bytes( data[offset : offset + 2], 'big' )
                        # skip Name len -> 2 bytes
                        offset += 2

                        sni_bytes = data[offset : offset + name_len]
                        sni_str = sni_bytes.decode('utf-8')
                        break # found SNI
                        
                    offset += ext_len # go to next ext
                    
            except IndexError:
                raise ValueError('TLS message: fragmented Client Hello message')

        return cls(content_type, version, payload_length, handshake_type, handshake_len, sni_str)

    def __str__(self):
        content_type_map = {
            20: 'Change Cipher Spec',
            21: 'Alert',
            22: 'Handshake',
            23: 'Application Data',
            24: 'Heartbeat'
        }
        content_type_str = content_type_map.get(self.content_type, f'Unknown ({self.content_type})')

        output_str = (
            f'-- TLS message:\n'
            f'type: {content_type_str}\n'
            f'length: {self.payload_length} bytes\n'
        )

        if self.content_type == 22 and self.handshake_type:
            handshake_type_map = {
                1: 'Client Hello',
                2: 'Server Hello',
                11: 'Certificate',
                12: 'Server Key Exchange',
                14: 'Server Hello Done',
                16: 'Client Key Exchange',
                20: 'Finished'
            }   
            handshake_type_str = handshake_type_map.get(self.handshake_type, f'Unknown ({self.handshake_type})')

            output_str += (
                f'handshake type: {handshake_type_str}\n'
                f'handshake length: {self.handshake_length} bytes\n'
            )

            if self.handshake_type == 1: # Client Hello
                sni_str = self.sni if self.sni else '<None>'

                output_str += f'domain (SNI): {sni_str}\n'

        return output_str

