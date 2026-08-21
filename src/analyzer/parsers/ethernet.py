
def parse_ethernet(data):
    dest = data[0:6]
    src = data[6:12]
    type = int.from_bytes(data[12:14], 'big')
    payload = data[14:]

    return dest, src, type, payload