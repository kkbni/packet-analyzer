import queue
import sys
import time
import signal

from .parsers.dispatch import CorruptedLayer

MAX_ID_STR_LEN = 3
MAX_IP_STR_LEN = 35
MAX_PROTO_STR_LEN = 15

command_mode = False

def pause_handler(sig, frame):
    # signal handler to enter command mode
    global command_mode
    command_mode = True

def print_help_manual():
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

def print_packet(packet_history: dict, packet_id: int):
    print(f'----- Packet {packet_id} -----\n')
    for layer in packet_history[packet_id]:
        if layer: print(layer)
    print('-' * 20 + '\n')

def print_packet_info(packet_history: dict, packet_id: int):
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

def run_command_mode(packet_history: dict, last_id: int | None):
    global command_mode

    print(
        '\n'
        '\n'
        '----- Entered COMMAND MODE -----\n'
        '( packet capture is running in the background )'
        )
    
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
            print_help_manual()

        elif not cmd:
            pass

        else:
            print(
                'Unrecognised command.\n'
                'For help type \'h\' or \'help\'.\n'
                )

        if cmd.isdigit() or cmd in ('n', 'next', 'p', 'prev'):
            print_packet(packet_history, packet_id)

    return last_id

def start_ui(
        packet_history: dict,
        packet_queue: queue.Queue
):
    global command_mode
    # hook the Ctrl+Z signal to pause_handler
    signal.signal(signal.SIGTSTP, pause_handler)
    
    print('Use Ctrl+Z to enter COMMAND MODE')
    print('----- Capture started -----\n')

    last_id = None

    # the main UI loop
    while True:
        try:
            if command_mode:
                run_command_mode(packet_history, last_id)
                        
            while not packet_queue.empty():
                packet_id = packet_queue.get()
                print_packet_info(packet_history, packet_id)

            time.sleep(0.05)

        except KeyboardInterrupt:
            # handles Ctrl+C to shutdown
            print('\nShutting down.\n')
            sys.exit(0)