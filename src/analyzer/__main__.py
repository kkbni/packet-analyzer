import signal
import queue
import threading
import sys
import time

from .capture import PacketCapturer
from .parsers.dispatch import CorruptedLayer, \
    parse_link_layer, parse_network_layer, \
    parse_ip_payload, parse_application_layer

MAX_ID_STR_LEN = 3
MAX_IP_STR_LEN = 35
MAX_PROTO_STR_LEN = 15

packet_history = {}
packet_queue = queue.Queue()

command_mode = False

def pause_handler(sig, frame):
    # signal handler to enter command mode
    global command_mode
    command_mode = True

def assemble_packet(link_pdu=None, net_pdu=None, inner_pdu=None, app_pdu=None):
    return (link_pdu, net_pdu, inner_pdu, app_pdu)

def capture_worker(capturer: PacketCapturer):
    packet_id = 0

    for data in capturer.capture():
        packet_id += 1

        # parse the packet
        link_pdu = parse_link_layer(data)
        if isinstance(link_pdu, CorruptedLayer):
            packet_history[packet_id] = assemble_packet(link_pdu)
            packet_queue.put(packet_id)
            continue

        network_pdu = parse_network_layer(
            link_pdu.ether_type, 
            link_pdu.payload
        )
        if isinstance(network_pdu, CorruptedLayer):
            packet_history[packet_id] = assemble_packet(link_pdu, network_pdu)
            packet_queue.put(packet_id)
            continue

        inner_proto_pdu = None
        if network_pdu.ip_proto and network_pdu.payload:
            inner_proto_pdu = parse_ip_payload(
                network_pdu.ip_proto, 
                network_pdu.payload
            )
        if isinstance(inner_proto_pdu, CorruptedLayer):
            packet_history[packet_id] = assemble_packet(link_pdu, network_pdu, inner_proto_pdu)
            packet_queue.put(packet_id)
            continue

        application_pdu = None
        if inner_proto_pdu and inner_proto_pdu.application_ports and inner_proto_pdu.payload:
            application_pdu = parse_application_layer(
                inner_proto_pdu.application_ports, 
                inner_proto_pdu.payload
            )
        packet_history[packet_id] = assemble_packet(link_pdu, network_pdu, inner_proto_pdu, application_pdu)
        packet_queue.put(packet_id)


def main():
    global command_mode
    # hook the Ctrl+Z signal to pause_handler
    signal.signal(signal.SIGTSTP, pause_handler)

    # create a capturer
    capturer = PacketCapturer('eth0')

    # start the packet capture
    worker = threading.Thread(target=capture_worker, args=[capturer], daemon=True)
    worker.start()

    print('Use Ctrl+Z to enter COMMAND MODE')
    print('----- Capture started -----\n')

    # the main UI loop
    while True:
        try:
            if command_mode:
                print(
                    '\n'
                    '\n'
                    '----- Entered COMMAND MODE -----\n'
                    '( packet capture is running in the background )'
                    )
                last_id = None
                
                while command_mode:
                    cmd = input('cmd> ').strip().lower()

                    if cmd.isdigit():
                        packet_id = int(cmd)
                        if packet_id not in packet_history:
                            print(f'Packet {packet_id} has not been captured yet.\n')
                            continue

                        last_id = packet_id


                    elif cmd in ('n', 'next'):
                        if last_id is None:
                            print('No packet viewed by ID before.\n')
                            continue

                        packet_id = last_id + 1
                        if packet_id not in packet_history:
                            print(f'Packet {packet_id} has not been captured yet.\n')
                            continue

                        last_id = packet_id

                    elif cmd in ('p', 'prev'):
                        if last_id is None:
                            print('No packet viewed by ID before.\n')
                            continue
                        packet_id = max(last_id - 1, 1)
                        last_id = packet_id

                    elif cmd in ('q', 'quit'):
                        print('\nShutting down.\n')
                        sys.exit(0)

                    elif cmd in ('r', 'resume'):
                        print('Resuming:\n')
                        command_mode = False

                    elif cmd in ('h', 'help'):
                        print(
                            '* Use Ctrl+C to SHUT DOWN the application.\n'
                            '* Use Ctrl+Z to enter COMMAND MODE.\n'
                            '\n'
                            '* In COMMAND MODE:\n'
                            '[id]       - Inspect a specific packet by its ID (e.g. 42)\n'
                            'n, next    - Inspect the next packet\n'
                            'p, prev    - Inspect the previous packet\n'
                            'r, resume  - Exit COMMAND MODE and resume the live feed\n'
                            'h, help    - Show this MANUAL\n'
                            'q, quit    - SHUT DOWN the application\n'
                        )

                    elif not cmd:
                        pass

                    else:
                        print(
                            'Unrecognised command.\n'
                            'For help type \'h\' or \'help\'.\n'
                            )

                    if cmd.isdigit() or cmd in ('n', 'next', 'p', 'prev'):
                        print(f'----- Packet {packet_id} -----\n')
                        for layer in packet_history[packet_id]:
                            if layer: print(layer)
                        print('-' * 20 + '\n')
                        
            while not packet_queue.empty():
                packet_id = packet_queue.get()
                link, net, inner, app = packet_history[packet_id]

                highest_layer = app or inner or net or link
                highest_layer_proto = f'{type(highest_layer).__name__}'

                src_ip, dest_ip = ('Unknown', 'Unknown')
                if net and not isinstance(net, CorruptedLayer):
                    src_ip, dest_ip = (net.src_ip, net.dest_ip)

                display_id_str = f'{packet_id:>{MAX_ID_STR_LEN}}'

                ip_str = f'{src_ip} -> {dest_ip}'
                display_ip_str = f'{ip_str:<{MAX_IP_STR_LEN}}'
                info_str = highest_layer.info() if hasattr(highest_layer, 'info') else ''

                display_info_str = f'{highest_layer_proto:<{MAX_PROTO_STR_LEN}}'
                if info_str: display_info_str += f' | {info_str}'

                print(f'{display_id_str} | {display_ip_str} | {display_info_str}')

            time.sleep(0.05)

        except KeyboardInterrupt:
            # handles Ctrl+C to shutdown
            print('\nShutting down.\n')
            sys.exit(0)

if __name__ == '__main__':
    main()