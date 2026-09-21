import queue
import threading

from .capture import PacketCapturer, capture_worker
from .ui import start_ui

def main():
    packet_history = {}
    packet_queue = queue.Queue()

    # create a capturer
    capturer = PacketCapturer('eth0')

    # start the packet capture in a background thread
    worker = threading.Thread(target=capture_worker, args=[capturer, packet_history, packet_queue], daemon=True)
    worker.start()

    # start the UI in the main thread
    start_ui(packet_history, packet_queue)

if __name__ == '__main__':
    main()