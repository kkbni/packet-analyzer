from dataclasses import dataclass

@dataclass
class HTTPMessage:
    SUPPORTED_VERSIONS = (
        'HTTP/1.0',
        'HTTP/1.1'
    )
    # with spaces to reduce probability 
    # of matching random binary data
    VALID_START_KEYWORDS = ( 
        b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', 
        b'OPTIONS ', b'PATCH ', b'TRACE ', b'CONNECT ', 
        b'HTTP/'
    )

    version: str # HTTP/1.1
    headers: dict[str, str]
    body: bytes
    method: str | None = None
    target: str | None = None
    status_code: int | None = None
    reason: str | None = None

    @classmethod
    def parse(cls, data: bytes):
        # check if the start is a valid HTTP/1.x keyword in plain text
        # if not -> the version used is unsupported
        if not data.startswith(cls.VALID_START_KEYWORDS):
            raise ValueError(
                f'HTTP message:\n'
                f'the version is not in SUPPORTED_VERSIONS -> {cls.SUPPORTED_VERSIONS}\n'
            )
        
        headers_data, separator, body = data.partition(b'\r\n\r\n')
        if not separator:
            raise ValueError('HTTP message: incomplete headers\n')

        lines = headers_data.split(b'\r\n')
        try:
            start_line = lines[0].decode('iso-8859-1') # ( req | res ) line
            header_lines = [ line.decode('iso-8859-1') for line in lines[1:] ]

        except UnicodeDecodeError as err:
            raise ValueError('HTTP message: invalid encoding\n') from err

        headers = {}
        for line in header_lines:
            if not line:
                continue

            name, separator, value = line.partition(':')
            if not separator or not name:
                raise ValueError('HTTP message: invalid header\n')
            
            headers[ name.strip().lower() ] = value.strip()

        parts = start_line.split(' ', 2)
        if start_line.startswith('HTTP/'):
            if len(parts) < 2:
                raise ValueError('HTTP message: invalid response line\n')
            
            try:
                status_code = int(parts[1])
            except ValueError as err:
                raise ValueError('HTTP message: invalid status code\n') from err

            version = parts[0].strip()
            reason = parts[2].strip() if len(parts) == 3 else ''

            if version not in cls.SUPPORTED_VERSIONS:
                raise ValueError(f'HTTP message: unsupported version -> {version}\n')

            return cls(version, headers, body, status_code=status_code, reason=reason)

        if len(parts) != 3 or not parts[2].startswith('HTTP/'):
            raise ValueError('HTTP message: invalid request line\n')

        version = parts[2].strip()

        if version not in cls.SUPPORTED_VERSIONS:
            raise ValueError(f'HTTP message: unsupported version -> {version}\n')

        method = parts[0].strip()
        target = parts[1].strip()

        return cls(version, headers, body, method=method, target=target)

    def __str__(self):
        if self.status_code is not None: # res
            first_line = f'{self.version} {self.status_code} {self.reason}'
        else: # req
            first_line = f'{self.method} {self.target} {self.version}'

        output_str = (
            f'-- HTTP message:\n'
            f'{first_line}\n'
        )

        if self.headers:
            for name, value in self.headers.items():
                output_str += f'{name}: {value}\n'

        if self.body:
            output_str += (
                f'\n'
                f'body length: { len(self.body) } bytes\n'
                f'body:\n'
            )

            body_len_lim = 200 # set the limit for preview
            body_str = self.body[:body_len_lim].decode('utf-8', errors='replace')

            if len(self.body) > body_len_lim:
                output_str += (
                    f'{body_str}\n'
                    f'... <Truncated> ...\n'
                )
            else:
                output_str += f'{body_str}\n'
                

        return output_str