# Advanced Networking & Security Labs

A hands-on portfolio of networking and cybersecurity projects built with **Python**, focusing on **TCP/IP**, **sockets**, **packet analysis**, **DNS**, **secure communication**, and **low-level protocol behavior**.

These projects were developed during the elective course **Advanced Computer Networks**  
(**רשתות מחשבים מתקדמות**) at **[Jerusalem College of Technology - JCT](https://www.jct.ac.il/en/)**, Jerusalem.

---

## What This Repository Shows

This repository demonstrates practical experience with:

- Python networking
- TCP client-server communication
- Custom application-layer protocols
- DNS enumeration
- Packet crafting with Scapy
- PCAP traffic analysis
- SYN Flood detection
- Secure communication concepts
- Diffie-Hellman key exchange
- RSA digital signatures
- HMAC integrity validation
- TCP Fast Open simulation

The focus of this repository is not only writing code, but understanding how network communication works behind the scenes.

---

## Tech Stack

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Networking](https://img.shields.io/badge/Networking-TCP%2FIP-green)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Packet%20Analysis-red)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Crafting-orange)

---

## Projects Overview

| Project | Main Focus | Source Code |
|--------|------------|-------------|
| Multi-Client Chat Application | TCP sockets, multiple clients, private messages, broadcast, blocking users | [Open Project](chat-application/) |
| Custom Message Protocol | Reliable message framing over TCP | [protocol.py](chat-application/protocol.py) |
| DNS Enumeration Tool | DNS queries, SOA records, A records, Scapy | [Open Project](dns-enumeration/) |
| Secure Communication | Diffie-Hellman, RSA signatures, HMAC, encryption logic | [Open Project](secure-communication/) |
| SYN Flood Detection | PCAP analysis, TCP flags, traffic anomaly detection | [Open Project](syn-flood-detection/) |
| TCP Fast Open Simulation | Raw packets, TCP handshake, cookies, HTTP-like request | [Open Project](tcp-fast-open/) |

---

# 1. Multi-Client Chat Application

## Overview

A TCP-based chat system that supports multiple connected clients at the same time.

The server uses `select` to manage several clients without creating a separate thread for each one.

## Features

- Multi-client TCP server
- Private messaging
- Broadcast messages
- Username registration
- User blocking
- Clean disconnection
- Custom message protocol

## Source Code

- [Client](chat-application/client.py)
- [Server](chat-application/server.py)
- [Protocol](chat-application/protocol.py)

## Supported Commands

```text
NAME <username>
GET_NAMES
MSG <username> <message>
MSG BROADCAST <message>
BLOCK <username>
EXIT
```

## Example

```text
NAME Levi
MSG BROADCAST Hello everyone
MSG David Hey David
BLOCK David
EXIT
```

## Skills Demonstrated

- TCP sockets
- Client-server architecture
- Non-blocking I/O
- Message routing
- Application-layer protocol design

---

# 2. Custom TCP Message Protocol

## Overview

TCP is a stream-based protocol, which means it does not automatically preserve message boundaries.

To solve this, I implemented a simple custom protocol using a fixed-size length field.

## Message Format

```text
[4-byte length][message content]
```

Example:

```text
0005HELLO
```

Meaning:

```text
0005 = message size
HELLO = message content
```

## Source Code

- [protocol.py](chat-application/protocol.py)

## Skills Demonstrated

- TCP message framing
- Reliable socket reading
- Encoding and decoding
- Protocol abstraction
- Separating networking logic from application logic

---

# 3. DNS Enumeration Tool

## Overview

A DNS enumeration tool built with **Scapy**.

The tool receives a target domain and a wordlist, then checks which subdomains exist by sending DNS queries.

## Source Code

- [dnsenum.py](dns-enumeration/dnsenum.py)
- [Wordlist](dns-enumeration/dnsenum.txt)

## Main Flow

1. Find the authoritative DNS server using an SOA query.
2. Resolve the authoritative DNS server IP.
3. Read possible subdomains from a wordlist.
4. Send DNS A-record queries.
5. Print discovered subdomains and IPv4 addresses.

## Example Usage

```bash
cd dns-enumeration
python dnsenum.py example.com dnsenum.txt
```

## Skills Demonstrated

- DNS protocol understanding
- SOA records
- A records
- UDP-based communication
- Packet crafting with Scapy
- Subdomain enumeration logic

---

# 4. Secure Client-Server Communication

## Overview

A simplified secure communication system between a client and a server.

The project combines several security concepts into one communication flow:

- Diffie-Hellman key exchange
- RSA digital signature
- Shared secret generation
- Key derivation
- XOR encryption logic
- HMAC integrity check

## Source Code

- [Client](secure-communication/client.py)
- [Server](secure-communication/server.py)

## Communication Flow

1. Client connects to the server.
2. Server sends RSA public parameters.
3. Server and client exchange Diffie-Hellman values.
4. Server signs its Diffie-Hellman value with RSA.
5. Both sides calculate the same shared secret.
6. The shared secret is split into:
   - Encryption key
   - MAC key
7. Client encrypts the message.
8. Client sends encrypted data with HMAC.
9. Server decrypts and verifies the message.

## Skills Demonstrated

- Secure protocol design
- Key exchange
- Digital signatures
- Hashing
- HMAC validation
- Message integrity
- Client-server security logic

## Note

This project is educational and uses simplified cryptographic values for learning purposes.

---

# 5. SYN Flood Detection Tool

## Overview

A defensive traffic analysis tool that reads a PCAP file and identifies suspicious IP addresses that may be involved in a SYN Flood attack.

The detection is based on TCP flag behavior.

## Source Code

- [Detection Script](syn-flood-detection/syn_detect.py)
- [Detected Attackers Output](syn-flood-detection/detected_attackers.txt)

## Detection Logic

The tool analyzes:

- SYN-only packets
- ACK-only packets
- Source IP behavior
- Destination traffic concentration
- Likely victim network
- Suspicion score per IP

## Suspicion Score

```text
score = SYN-only packets / (1 + ACK-only packets)
```

A source IP with many SYN packets and very few ACK packets is considered more suspicious.

## Skills Demonstrated

- PCAP analysis
- TCP flag inspection
- SYN Flood behavior understanding
- Traffic anomaly detection
- False-positive reduction
- Defensive cybersecurity analysis

---

# 6. TCP Fast Open Simulation

## Overview

A low-level simulation of **TCP Fast Open** using Scapy.

TCP Fast Open allows data to be sent during the TCP handshake in repeated connections.

This project simulates that behavior using raw packets, cookies, and an HTTP-like request.

## Source Code

- [Client](tcp-fast-open/client.py)
- [Server](tcp-fast-open/server.py)

## Main Flow

1. Client sends a SYN packet.
2. Server replies with SYN+ACK and a cookie.
3. Client saves the cookie.
4. Client sends another SYN packet with:
   - The cookie
   - An HTTP-like request
5. Server validates the cookie.
6. Server sends the requested response.

## Supported Requests

```text
GET /Name HTTP/1.1
GET /ID HTTP/1.1
```

## Skills Demonstrated

- TCP handshake behavior
- SYN and SYN+ACK packets
- Raw packet crafting
- Packet sniffing
- Cookie-based validation
- TCP Fast Open concept
- Low-level protocol analysis

---

## How to Run

Some projects use only Python standard libraries.

Projects that use packet crafting or packet sniffing require **Scapy**.

Install Scapy:

```bash
pip install scapy
```

Run each project from its own folder.

Example:

```bash
cd chat-application
python server.py
```

Then open another terminal:

```bash
python client.py
```

For Scapy-based projects, administrator/root permissions may be required.

---

## Repository Structure

```text
.
├── README.md
│
├── chat-application/
│   ├── client.py
│   ├── protocol.py
│   └── server.py
│
├── dns-enumeration/
│   ├── dnsenum.py
│   └── dnsenum.txt
│
├── secure-communication/
│   ├── client.py
│   └── server.py
│
├── syn-flood-detection/
│   ├── detected_attackers.txt
│   └── syn_detect.py
│
└── tcp-fast-open/
    ├── client.py
    └── server.py
```

---

## Key Skills Highlighted

This repository highlights practical skills in:

- Python development
- Network programming
- TCP/IP communication
- Socket programming
- Protocol design
- Packet analysis
- Scapy
- DNS
- Cybersecurity fundamentals
- Secure communication
- Defensive traffic analysis
- Low-level networking

---

## Professional Focus

These projects strengthened my interest in:

- Network Security
- Cybersecurity
- Backend Communication
- Protocol Design
- Packet Analysis
- Secure Software Development
- Infrastructure and Systems Programming

---

## Disclaimer

This repository is intended for educational, defensive, and research purposes only.

The security-related projects should only be used in controlled environments or on systems where permission was granted.
