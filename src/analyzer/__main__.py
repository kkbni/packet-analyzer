from .capture import PacketCapturer

def main():
    capturer = PacketCapturer('eth0')

    for packet in capturer.capture():
        print(packet.hex())

if __name__ == '__main__':
    main()