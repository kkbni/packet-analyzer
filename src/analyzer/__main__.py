from .capture import PacketCapturer
from .parsers.ethernet import EthernetFrame

def main():
    print('----- Starting capture:\n')
    delim_str = '-' * 30 + '\n'

    capturer = PacketCapturer('eth0')

    for data in capturer.capture():

        print(delim_str)
        frame = EthernetFrame.parse(data)
        print(frame)

if __name__ == '__main__':
    main()