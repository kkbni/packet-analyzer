from .capture import PacketCapturer
from .parsers.ethernet import parse_ethernet

def main():
    print('Starting capture:')

    capturer = PacketCapturer('eth0')

    for packet in capturer.capture():
        dest, src, type, data = parse_ethernet(packet)

        print(f'dest: {dest.hex(':')}\nsrc: {src.hex(':')}\ntype: {type:#06x}\ndata:\n{data.hex()}\n')

if __name__ == '__main__':
    main()