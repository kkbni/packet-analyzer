from .capture import PacketCapturer
from .parsers.ethernet import EthernetFrame
from .parsers.ipv4 import IPv4Packet

def main():
    print('----- Starting capture:\n')
    delim_str = '-' * 30 + '\n'

    capturer = PacketCapturer('eth0')

    for data in capturer.capture():
        print(delim_str)

        frame = EthernetFrame.parse(data)
        print(frame)

        packet = IPv4Packet.parse(frame.payload)
        print(packet)
        

if __name__ == '__main__':
    main()