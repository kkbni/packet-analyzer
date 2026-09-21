import argparse
import sys
import queue
import threading

from .capture import PacketCapturer, capture_worker
from .ui import start_ui

# error codes
ENODEV = 19
EPERM = 1

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '-i', '--interface',
        type=str,
        default='eth0',
    )
    args = arg_parser.parse_args()

    # try to bind the interface
    try:
        # create a capturer
        capturer = PacketCapturer(args.interface)
    except OSError as e:
        if e.errno == ENODEV:
            print(f'Error: interface \'{args.interface}\' doesn\'t exist.')
            print('Check available interfaces with "ifconfig".\n')
        elif e.errno == EPERM:
            print('Error: operation not permitted.')
            print('Raw sockets require elevated privileges. Did you forget \'sudo\'?\n')
        else:
            print(f'Error while binding to \'{args.interface}\': {e}\n')
        sys.exit(1)

    packet_history = {}
    packet_queue = queue.Queue()

    # start the packet capture in a background thread
    worker = threading.Thread(target=capture_worker, args=[capturer, packet_history, packet_queue], daemon=True)
    worker.start()

    # start the UI in the main thread
    start_ui(packet_history, packet_queue)

if __name__ == '__main__':
    main()