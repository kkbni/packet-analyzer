# Packet Analyzer (Minimal Python Packet Sniffer)

A custom network packet sniffer built in Python. This project captures raw network traffic directly from the wire and parses the binary payloads up the TCP/IP stack to extract application-level data.

## Features (Current Version)

* **Raw Socket Capture:** Utilizes Python's built-in `socket` module to capture raw ethernet frames on the `eth0` interface.

* **Modular Parsing Architecture:** Dispatches parsing logic dynamically using protocol identifiers to keep layers strictly separated.

* **Supported Protocols:**
  * **Link Layer:** Ethernet
  * **Network Layer:** IPv4, IPv6, ARP, ICMPv4, ICMPv6
  * **Transport Layer:** TCP, UDP
  * **Application Layer:** DNS, HTTP, HTTPS/TLS
  
  *for TLS: extracts SNI from the plaintext Client Hello*

* **Interactive Terminal UI:** Multithreaded architecture that separates background packet capture from a live-updating display.

## Architecture Overview
The sniffer follows a layer-by-layer unwrapping approach:

1. **Capture:** The `PacketCapturer` binds an `AF_PACKET` raw socket to the network interface, yielding raw byte strings.

2. **Main Loop:** The `__main__.py` module runs the pipeline, passing the payload sequentially through the stack: Link -> Network -> IP Payload -> Application.

3. **Dispatcher:** The `dispatch.py` acts as a traffic router. It uses dictionaries to match IDs (e.g., `ETHER_TYPE_IPV4 = 0x0800` or `APP_PORT_HTTPS = 443`) to their specific parser classes. It also acts as a shield, using centralized exception handling to drop malformed packets without crashing the sniffer.

## Interactive Interface
The analyzer includes a custom interactive command-line interface (CLI) to inspect traffic without stopping the capture:

* **Live Feed:** Displays real-time summaries of network traffic including protocol names, IP flows, and dynamic top-layer summaries.

* **Command Mode:** Pressing `Ctrl+Z` pauses the live feed and opens an interactive shell while the packet capture continues in a background thread.

* **Inspection:** Users can inspect the fully decoded, multi-layer hierarchy of a specific packet by typing its ID.

* **Navigation:** `next` (`n`) and `prev` (`p`) commands allow users to step through the packet history chronologically.

## Project Structure
The package is organized for scalability:

```text
packetTracer/
├── src/
│   └── analyzer/
│       ├── __init__.py           # Package initialization
│       ├── __main__.py           # The main loop
│       ├── capture.py            # AF_PACKET raw socket capture
│       ├── dispatch.py           # Protocol routing maps and error handling
│       ├── ui.py                 # Interactive CLI state machine
│       └── parsers/              # Protocol-specific parser definitions
│           ├── application/      
│           ├── link/             
│           ├── network/          
│           └── transport/        
├── .dockerignore                 # Excludes local artifacts from container
├── .gitignore                    # Excludes local artifacts from version control
├── Dockerfile                    # Container build instructions
└── README.md                     # Project documentation      
```

## Running the Sniffer
Because this tool uses `SOCK_RAW` to bypass the OS network stack and access Layer 2 frames, it requires elevated system privileges to run. 

```bash
# Execute the module with root privileges (defaults to capturing on eth0)
sudo python3 -m src.analyzer

# Specify a custom network interface (e.g. wlan0)
sudo python3 -m src.analyzer -i wlan0

# View the help menu
python3 -m src.analyzer -h
```

## Docker Containerization
The analyzer can be run in a lightweight Docker container. Because it requires raw network access and an interactive terminal, specific runtime flags are needed.

```bash
# 1. Build the image
docker build -t packet-analyzer .

# 2. Run interactively with host networking and raw socket capabilities
docker run -it --network host --cap-add=NET_RAW packet-analyzer -i eth0
```

*Note: The `-it` flag ensures Command Mode works, `--network host` allows the container to see the host's actual interfaces, and `--cap-add=NET_RAW` provides necessary socket permissions.*

## Future Work
*(In development)*

* **Display Filters:** Implement interactive filtering within the CLI to isolate specific traffic without dropping packets.

* **TCP Reassembly:** Implement connection tracking to stitch together fragmented HTTP responses.

* **Extended TLS Parsing:** Map out additional variable-length fields and extensions in the TLS Handshake.

* **Protocol Expansion:** Add parsing support for additional protocols across the stack, such as DHCP, OSPF, etc.

* **PCAP Export:** Add a binary writer to save captured traffic to `.pcap` files for testing and debugging.
