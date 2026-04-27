import socket
import random
import hashlib

# -------------------------
# Diffie-Hellman
# -------------------------
def dh_public(g, secret, p):
    return pow(g, secret, p)

def dh_secret(other_public, secret, p):
    return pow(other_public, secret, p)

# -------------------------
# Key derivation
# -------------------------
def derive_keys(secret_16bit: int):
    secret_16bit &= 0xFFFF
    enc_key = (secret_16bit >> 8) & 0xFF
    mac_key = secret_16bit & 0xFF
    return enc_key, mac_key

# -------------------------
# XOR
# -------------------------
def xor_bytes(data: bytes, key_byte: int) -> bytes:
    key_byte &= 0xFF
    return bytes([b ^ key_byte for b in data])

# -------------------------
# Hash + HMAC
# -------------------------
def hash16(data: bytes) -> int:
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest[:2], "big")

def compute_hmac(message: bytes, mac_key: int) -> int:
    return hash16(message + bytes([mac_key & 0xFF]))

# -------------------------
# Network helpers
# -------------------------
def send_line(sock, text: str):
    sock.sendall((text + "\n").encode())

def recv_line(sock) -> str:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed while reading line.")
        buf += chunk
    return buf[:-1].decode()

# -------------------------
# Main client logic
# -------------------------
def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 5000))

    # Step 2: Send "Hello"
    send_line(client, "Hello")

    # Step 3: Receive N and E
    N_str, e_str = recv_line(client).split(",")
    N = int(N_str)
    e = int(e_str)

    # Step 4: Receive g and p
    g_str, p_str = recv_line(client).split(",")
    g = int(g_str)
    p = int(p_str)

    # Step 5: Choose a, compute A, send to server
    a = random.randint(2, 60000)
    A = dh_public(g, a, p)
    send_line(client, str(A))

    # Step 8+9: Receive signature, recover B using RSA public key
    signature = int(recv_line(client))
    B = pow(signature, e, N)

    # Step 10: Compute shared secret
    secret_client = dh_secret(B, a, p)

    # Step 11: Print shared secret
    print("CLIENT: Shared secret =", secret_client)

    # Step 12: Derive keys
    enc_key, mac_key = derive_keys(secret_client)
    print("CLIENT: Enc key =", enc_key, "| MAC key =", mac_key)

    # Step 13: Prepare message -> HMAC -> encrypt(message || hmac)
    message = b"Hello Secure World"
    hmac_value = compute_hmac(message, mac_key)
    hmac_bytes = hmac_value.to_bytes(2, "big")

    payload = message + hmac_bytes
    encrypted = xor_bytes(payload, enc_key)

    # Send length-prefixed binary payload
    send_line(client, str(len(encrypted)))
    client.sendall(encrypted)

    client.close()

if __name__ == "__main__":
    main()
