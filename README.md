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
  
  > for TLS: extracts SNI from the plaintext Client Hello

## Architecture Overview
The sniffer follows a layer-by-layer unwrapping approach:

1. **Capture:** The `PacketCapturer` binds an `AF_PACKET` raw socket to the network interface, yielding raw byte strings.

2. **Main Loop:** The `__main__.py` module runs the pipeline, passing the payload sequentially through the stack: Link -> Network -> IP Payload -> Application.

3. **Dispatcher:** The `dispatch.py` acts as a traffic router. It uses dictionaries to match IDs (e.g., `ETHER_TYPE_IPV4 = 0x0800` or `APP_PORT_HTTPS = 443`) to their specific parser classes. It also acts as a shield, using centralized exception handling to drop malformed packets without crashing the sniffer .

## Project Structure
The package is organized for scalability:

```text
src/analyzer/
├── __init__.py           # Package initialization
├── __main__.py           # The main loop
├── capture.py            # AF_PACKET raw socket capture
├── dispatch.py           # Protocol routing maps and error handling
└── parsers/              # Protocol-specific parser definitions
    ├── application/      
    ├── link/             
    ├── network/          
    └── transport/        
```

## Running the Sniffer
Because this tool uses `SOCK_RAW` to bypass the OS network stack and access Layer 2 frames, it requires elevated system privileges to run. 

```bash
# Execute the module with root privileges
sudo python3 -m src.analyzer
```

## Future Work
*(In development)*

* **UX Improvements:** Refine terminal output and overall user interaction.

* **TCP Reassembly:** Implement connection tracking to stitch together fragmented HTTP responses.

* **Extended TLS Parsing:** Map out additional variable-length fields and extensions in the TLS Handshake.

* **Protocol Expansion:** Add parsing support for additional protocols across the stack, such as DHCP, OSPF, etc.

* **PCAP Export:** Add a binary writer to save captured traffic to `.pcap` files for testing and debugging.
