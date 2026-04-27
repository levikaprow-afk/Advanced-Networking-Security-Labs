import sys
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1


# ============================================================================
# 1) Find the authoritative DNS server (SOA query) using SCAPY
# ============================================================================

def find_authoritative_dns(domain):
    # Print a status message so the user knows what is happening.
    print("[+] Sending SOA query using Scapy...")

    # Build a DNS packet to ask Google DNS (8.8.8.8) for an SOA record.
    # rd=1 means "recursive query"
    # qname=domain is the domain we want information about
    # qtype="SOA" means we are specifically asking for an SOA record.
    pkt = IP(dst="8.8.8.8")/UDP()/DNS(rd=1, qd=DNSQR(qname=domain, qtype="SOA"))

    # Send the packet and wait for one reply (sr1 = send & receive 1 packet).
    # timeout=5 means it will wait up to 5 seconds.
    ans = sr1(pkt, timeout=5, verbose=0)

    # If there is no answer or no ANSWER section, we cannot continue.
    if ans is None or ans.an is None:
        print("[-] Could not obtain SOA record.")
        sys.exit(1)

    # Loop through all records in the ANSWER section.
    # We are looking for the SOA record (type = 6).
    for i in range(ans.ancount):
        rr = ans.an[i]      # rr = “resource record number i”
        
        # If this record is SOA (type 6), then it contains the mname field.
        if rr.type == 6:
            # rr.mname is the primary DNS server for the domain.
            # It may be bytes or a string — decode if needed.
            mname = rr.mname.decode() if isinstance(rr.mname, bytes) else rr.mname

            print(f"[+] SOA mname found: {mname}")

            # Remove the trailing "." (DNS formats usually end with a dot).
            return mname.rstrip(".")

    # If we got here, we received an SOA response but no usable mname.
    print("[-] SOA answer received but no mname found.")
    sys.exit(1)



# ============================================================================
# 2) Query A records from the authoritative DNS server
# ============================================================================

def query_A_records(dns_ip, fqdn):
    # We want to ask the authoritative DNS server (dns_ip)
    # for the IPv4 address (A record) of the full domain name (fqdn).

    # Build a DNS packet that asks:
    # "What is the A record of fqdn?"
    pkt = IP(dst=dns_ip)/UDP()/DNS(
        rd=1,                      # rd = recursion desired ("please resolve this")
        qd=DNSQR(qname=fqdn, qtype="A")  # qname = the domain we ask about, qtype="A" = IPv4
    )

    # Send the packet and wait for ONE reply (sr1 = send/receive 1 response)
    # timeout=3 -> wait up to 3 seconds
    # verbose=0 -> do not print Scapy debug info
    ans = sr1(pkt, timeout=3, verbose=0)

    # If the DNS server did not answer, or answer has no "answer" section (an),
    # then we return an empty list because there are no IPs.
    if ans is None or ans.an is None:
        return []

    # List to store all the IPv4 addresses we find
    ips = []

    # Go through ONLY the ANSWER section, as the professor requires.
    # ans.ancount = number of answer records.
    for i in range(ans.ancount):
        rr = ans.an[i]   # rr = a single answer record

        # If the record type is 1, it means A RECORD (IPv4)
        if rr.type == 1:
            ips.append(rr.rdata)   # rdata = the actual IPv4 address

    # Remove duplicates by converting list -> set -> list again
    ips = list(set(ips))

    # Return the final list of IPv4 addresses for that subdomain
    return ips


# ============================================================================
# 3) MAIN SCRIPT
# ============================================================================

def main():
    # We must receive exactly 2 arguments: <domain> and <wordlist>.
    # sys.argv[0] = program name, argv[1] = domain, argv[2] = wordlist.
    if len(sys.argv) != 3:
        print("Usage: python dnsenum.py <domain> <wordlist>")
        sys.exit(1)

    # Store the domain to scan and the wordlist file.
    domain = sys.argv[1]
    wordlist = sys.argv[2]

    print(f"[+] Target domain: {domain}")

    # STEP 1 — Find the authoritative DNS server using SOA query.
    # This tells us which DNS is responsible for the domain.
    auth_dns = find_authoritative_dns(domain)
    print(f"[+] Authoritative DNS server: {auth_dns}")

    # STEP 2 — Ask Google DNS (8.8.8.8) to give us the IP of that server.
    pkt = IP(dst="8.8.8.8")/UDP()/DNS(rd=1, qd=DNSQR(qname=auth_dns, qtype="A"))
    ans = sr1(pkt, timeout=5, verbose=0)

    # If no answer → stop.
    if ans is None or ans.an is None:
        print("[-] Could not resolve authoritative DNS IP.")
        sys.exit(1)

    # Take the first IP returned.
    dns_ip = ans.an[0].rdata
    print(f"[+] Authoritative DNS IP: {dns_ip}\n")

    # STEP 3 — Load the wordlist containing subdomain names to test.
    try:
        with open(wordlist, "r") as f:
            subs = [x.strip() for x in f if x.strip()]
    except:
        print("[-] Cannot open wordlist file.")
        sys.exit(1)

    print("[+] Starting DNS enumeration...\n")

    results = {}
    total_ips = 0

    # For each word, build a subdomain and test it.
    for s in subs:
        fqdn = f"{s}.{domain}"    # Example: "mail" + "jct.ac.il" → "mail.jct.ac.il"
        ips = query_A_records(dns_ip, fqdn)

        # If the DNS returns at least one IP → subdomain exists.
        if ips:
            results[fqdn] = ips
            print(f"[FOUND] {fqdn}")
        else:
            print(f"[NO]    {fqdn}")

    # Final output
    print("\n===== RESULTS =====")

    for host, ips in results.items():
        print(f"{host}:")
        for ip in ips:
            print(f"   -> {ip}")
        print()
        total_ips += len(ips)   # count all IPv4 addresses found

    print(f"[+] Total subdomains found: {len(results)}")
    print(f"[+] Total IPv4 addresses: {total_ips}")


if __name__ == "__main__":
    main()
