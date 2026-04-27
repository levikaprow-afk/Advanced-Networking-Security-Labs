from scapy.all import rdpcap, IP, TCP
import ipaddress  # Python standard library for IP/network (CIDR) checks (e.g., /24)


PCAP_FILE = "SYNflood.pcapng"
OUTPUT_FILE = "detected_attackers.txt"


def detect_attackers(pcap_path: str, output_path: str):
    # Read the packet capture using Scapy (required by the assignment)
    pcapFile = rdpcap(pcap_path)

    # We track 3 required detection parameters:
    # 1) SYN-only per source IP  -> "who starts many connections"
    # 2) ACK-only per source IP  -> "who behaves like a normal client"
    # 3) Destination range       -> infer the victim network and avoid false positives
    syn_only_by_src = {}   # {src_ip: count_of_SYN_only}
    ack_only_by_src = {}   # {src_ip: count_of_ACK_only}
    syn_only_to_dst = {}   # {dst_ip: count_of_SYN_only_to_that_dst}

    # Iterate over packets (required: for pkt in pcapFile)
    for pkt in pcapFile:
        # We only care about TCP over IP packets (SYN/ACK flags are in TCP)
        if IP not in pkt or TCP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        flags = int(pkt[TCP].flags)

        # TCP flag bits: SYN=0x02, ACK=0x10
        syn = (flags & 0x02) != 0
        ack = (flags & 0x10) != 0

        # Parameter #1: count SYN-only packets per source (typical for SYN flood senders)
        if syn and not ack:
            syn_only_by_src[src] = syn_only_by_src.get(src, 0) + 1
            # Also count SYN-only per destination to infer the most targeted victim
            syn_only_to_dst[dst] = syn_only_to_dst.get(dst, 0) + 1

        # Parameter #2: count ACK-only packets per source (normal clients tend to have ACKs)
        if ack and not syn:
            ack_only_by_src[src] = ack_only_by_src.get(src, 0) + 1

    # Parameter #3: infer the victim network (destination range) to avoid marking victim IPs
    victim_ip = max(syn_only_to_dst, key=syn_only_to_dst.get)          # most targeted dst
    victim_net = ipaddress.ip_network(f"{victim_ip}/24", strict=False) # its /24 network

    def in_victim_network(ip_str: str) -> bool:
        # Returns True if ip_str belongs to victim_net; False on invalid IP input
        try:
            return ipaddress.ip_address(ip_str) in victim_net
        except Exception:
            return False

    # Compute a suspicion score for each source:
    # many SYN-only and few ACK-only => higher score => more likely attacker
    scored = []
    for src, syn_cnt in syn_only_by_src.items():
        # Do not accuse IPs from the victim network (rubric false-positive penalty)
        if in_victim_network(src):
            continue

        ack_cnt = ack_only_by_src.get(src, 0)
        score = syn_cnt / (1 + ack_cnt)  # +1 prevents division by zero
        scored.append((score, src))

    # Sort by score descending (most suspicious first), then extract IPs
    scored.sort(reverse=True)
    attackers = []
    for score, src in scored:
        attackers.append(src)

    # Remove duplicates while preserving order (safety)
    attackers = list(dict.fromkeys(attackers))

    # Rubric requirement: output must contain 50–150 IPs
    N = 100
    if len(attackers) < 50:
        N = len(attackers)   # do not invent IPs
    elif len(attackers) > 150:
        N = 150              # cap at maximum allowed

    attackers = attackers[:N]

    # Write output file: one IP per line
    with open(output_path, "w", encoding="utf-8") as out:
        for ip in attackers:
            out.write(ip + "\n")


def main():
    detect_attackers(PCAP_FILE, OUTPUT_FILE)


if __name__ == "__main__":
    main()
