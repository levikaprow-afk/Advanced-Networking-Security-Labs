from scapy.all import *
import time

PORT = 56789

show_interfaces()
conf.iface = dev_from_index(1)   # Select the loopback interface

SERVER_IP = "127.0.0.1"
CLIENT_PORT_1 = 12345   # First TCP connection
CLIENT_PORT_2 = 12346   # Second TCP connection (TFO)

""" Use prints after every step to show that it is completed """

# step 1 - send SYN

client_seq = 1000  # Client initial sequence number

syn = IP(dst=SERVER_IP) / TCP(
    sport=CLIENT_PORT_1,   # Client source port
    dport=PORT,            # Server destination port
    flags="S",             # SYN flag
    seq=client_seq
)

send(syn, verbose=False)
print("[CLIENT] Step 1 completed: SYN sent")

# step 2 - use proper filter to capture server's SYN ACK, keep the cookie

pkt2 = sniff(
    count=1,
    filter=f"tcp src port {PORT} and tcp dst port {CLIENT_PORT_1} "
           f"and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0"
)[0]

server_seq = pkt2[TCP].seq    # Server sequence number
cookie = pkt2[Raw].load      # Cookie from TCP payload

print("[CLIENT] Step 2 completed: SYN+ACK received, cookie saved")

# step 3 - send ACK

ack = IP(dst=SERVER_IP) / TCP(
    sport=CLIENT_PORT_1,
    dport=PORT,
    flags="A",               # ACK flag
    seq=client_seq + 1,
    ack=server_seq + 1
)

send(ack, verbose=False)
print("[CLIENT] Step 3 completed: ACK sent")

# step 4 -

time.sleep(1)

# A. ask the user if to ask for Name or ID (input)
choice = input("Enter request (Name / ID): ").strip()

# B. send SYN with the cookie, plus an HTTP request
http_get = f"GET /{choice} HTTP/1.1\r\n\r\n"

tfo_syn = IP(dst=SERVER_IP) / TCP(
    sport=CLIENT_PORT_2,    # New client port for TFO connection
    dport=PORT,
    flags="S",              # SYN flag
    seq=3000
) / Raw(load=cookie + http_get.encode())  # Cookie + HTTP request

send(tfo_syn, verbose=False)
print("[CLIENT] Step 4 completed: TFO SYN sent")

# step 5 -

# A. Use proper filter to capture server's response
pkt5 = sniff(
    count=1,
    filter=f"tcp src port {PORT} and tcp dst port {CLIENT_PORT_2} "
           f"and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0"
)[0]

# B. Extract the data from the HTTP header and print it
data = pkt5[Raw].load.decode()
body = data.split("\r\n\r\n", 1)[1]

print("[CLIENT] Step 5 completed: Server response received")
print("----- RESPONSE -----")
print(body)
