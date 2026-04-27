from scapy.all import *
import time
import os

PORT = 56789

show_interfaces()
conf.iface = dev_from_index(1)   # Select the loopback interface

""" Use prints after every step to show that it is completed """

# Generate a 64-bit cookie (8 bytes)
COOKIE = os.urandom(8)

# step 1 - use proper filter to capture the client SYN

print("[SERVER] Step 1: Waiting for client SYN")

pkt1 = sniff(
    count=1,
    filter="tcp dst port 56789 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
)[0]

client_ip = pkt1[IP].src
client_port = pkt1[TCP].sport
client_seq = pkt1[TCP].seq

print("[SERVER] Step 1 completed: Client SYN received")

# step 2 - send SYN ACK along with a cookie (64 bit of your choice)

server_seq = 5000  # Server initial sequence number

syn_ack = IP(dst=client_ip) / TCP(
    sport=PORT,              # Server port
    dport=client_port,       # Client port
    flags="SA",              # SYN + ACK
    seq=server_seq,
    ack=client_seq + 1       # Acknowledge client's SYN
) / Raw(load=COOKIE)         # Send cookie as TCP payload

send(syn_ack, verbose=False)
print("[SERVER] Step 2 completed: SYN+ACK with cookie sent")

# step 3 - use proper filter to capture the client ACK

sniff(
    count=1,
    filter=f"tcp src port {client_port} and tcp dst port {PORT} and tcp[tcpflags] & tcp-ack != 0"
)

print("[SERVER] Step 3 completed: Client ACK received")

# step 4 -
# A. Use proper filter to capture the client SYN
# B. Check the cookie (if there is one)

print("[SERVER] Step 4: Waiting for TFO SYN")

pkt4 = sniff(
    count=1,
    filter="tcp dst port 56789 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
)[0]

payload = pkt4[Raw].load              # [cookie][HTTP request]
recv_cookie = payload[:8]             # First 8 bytes = cookie
http_req = payload[8:].decode()       # Remaining bytes = HTTP request

if recv_cookie != COOKIE:
    print("[SERVER] Invalid or unknown cookie")
    exit()

print("[SERVER] Step 4 completed: Valid cookie received")

# step 5 -
# A. If the cookie is known, send ACK and the HTTP data requested
# B. If the cookie is not known, or no cookie - finish running

if http_req.startswith("GET /Name HTTP/1.1"):
    body = "YOUR NAME"
elif http_req.startswith("GET /ID HTTP/1.1"):
    body = "YOUR_ID"
else:
    print("[SERVER] Invalid HTTP request")
    exit()

http_resp = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    f"Content-Length: {len(body)}\r\n"
    "\r\n"
    f"{body}"
)

response = IP(dst=client_ip) / TCP(
    sport=PORT,
    dport=pkt4[TCP].sport,
    flags="SA",               # SYN + ACK
    seq=server_seq + 1,
    ack=pkt4[TCP].seq + 1
) / Raw(load=http_resp)

send(response, verbose=False)
print("[SERVER] Step 5 completed: HTTP response sent")
