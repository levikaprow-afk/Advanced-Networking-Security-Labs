import socket
import random
import math
import hashlib

# -------------------------
# RSA (server only)
# -------------------------
def generate_rsa_keys():
    # Server chooses two secret prime numbers
    P = 263
    Q = 283

    # N is shared by public and private keys
    N = P * Q

    # phi links the public exponent (e) to the private exponent (d)
    # phi does NOT need to be prime
    phi = (P - 1) * (Q - 1)

    # Public exponent
    # It only needs to be coprime with phi
    e = 65537  # common default value

    # If not coprime, try other odd values
    if math.gcd(e, phi) != 1:
        e = 17
        while math.gcd(e, phi) != 1:
            e += 2

    # Private exponent: modular inverse of e
    # (e * d) mod phi == 1
    d = pow(e, -1, phi)

    # Public key: (N, e)
    # Private key: d
    return N, e, d


def rsa_sign(value_int, d, N):
    # Digitally signs a number using the server's private key
    # value_int is the Diffie-Hellman value B (not a message)
    # signature = B^d mod N
    return pow(value_int, d, N)


# -------------------------
# Diffie-Hellman (both sides)
# -------------------------
def dh_params_16bit():
    # p must be prime, < 65535. g can be any small number for this exercise.
    p = 49157
    g = 5
    return g, p

def dh_public(g, secret, p):
    # Creates a public Diffie-Hellman value
    # Uses a private secret to generate a value safe to send
    # Example: A = g^a mod p or B = g^b mod p
    return pow(g, secret, p)


def dh_secret(other_public, secret, p):
    # Computes the shared secret
    # Uses the other side's public value and our private secret
    # Client: secret = B^a mod p
    # Server: secret = A^b mod p
    return pow(other_public, secret, p)

# -------------------------
# Key derivation (both sides)
# -------------------------
def derive_keys(secret_16bit):
    # Split the 16-bit shared secret into two 8-bit keys
    # Upper 8 bits -> encryption key
    # Lower 8 bits -> MAC key
    enc_key = (secret_16bit >> 8) & 0xFF
    mac_key = secret_16bit & 0xFF
    return enc_key, mac_key


# -------------------------
# XOR (both sides)
# -------------------------
def xor_bytes(data, key_byte):
    # Symmetric encryption using XOR
    # Same function encrypts and decrypts
    # Without the key, data looks random
    return bytes([b ^ key_byte for b in data]) # For each byte b in data: c = b ⊕ key_byte


# -------------------------
# Hash + HMAC (both sides)
# -------------------------
def hash16(data: bytes) -> int:

    # Compute SHA-256 hash of the data (256 bits)
    digest = hashlib.sha256(data).digest()

    # Take the first 2 bytes (most significant bytes)
    # This reduces the hash to 16 bits, as required by the exercise
    return int.from_bytes(digest[:2], "big")


def compute_hmac(message: bytes, mac_key: int) -> int:
    # hash(message + MAC)
    return hash16(message + bytes([mac_key & 0xFF]))

# -------------------------
# Network helpers
# -------------------------
def send_line(conn, text: str):  # conn = direct communication channel with the client
    conn.sendall((text + "\n").encode())  
    # add newline to mark end of message
    # encode string to bytes
    # send all bytes through the socket


def recv_line(conn) -> str:
    buf = b""                          # buffer to store received bytes
    while not buf.endswith(b"\n"):     # read until newline (end of message)
        chunk = conn.recv(1)           # read exactly 1 byte from socket (one letter in ascii)
        if not chunk:                  # connection closed unexpectedly
            raise ConnectionError("Connection closed while reading line.")
        buf += chunk                   # append byte to buffer
    return buf[:-1].decode()            # remove '\n' and convert to string


# -------------------------
# Main server 
# -------------------------
def main():
    print("SERVER: Starting...")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 5000))
    server_socket.listen(1)

    conn, addr = server_socket.accept()
    print("SERVER: Client connected:", addr)

    # Step 2: Receive "Hello"
    hello = recv_line(conn)
    print("SERVER: Received:", hello)

    # Step 1+3: RSA keys, send N and E only
    N, e, d = generate_rsa_keys()
    send_line(conn, f"{N},{e}") # send to the client

    # Step 4: Send DH params g,p
    g, p = dh_params_16bit()
    send_line(conn, f"{g},{p}")

    # Step 5: Receive A from client
    A = int(recv_line(conn))
    print("SERVER: Received A =", A)

    # Step 6: Choose b, compute shared secret using A
    b = random.randint(2, 60000)
    secret_server = dh_secret(A, b, p)

    # Step 7: Compute B (do not send B directly)
    B = dh_public(g, b, p)

    # Step 8: Sign B with RSA private key and send signature
    signature = rsa_sign(B, d, N)
    send_line(conn, str(signature))

    # Step 11: Print shared secret
    print("SERVER: Shared secret =", secret_server) # secured key

    # Step 12: Derive enc_key and mac_key
    enc_key, mac_key = derive_keys(secret_server)
    print("SERVER: Enc key =", enc_key, "| MAC key =", mac_key)

    # Step 14: Receive encrypted payload (binary)
    # We'll receive length-prefixed for reliability
    length = int(recv_line(conn))
    encrypted = b""
    while len(encrypted) < length:
        encrypted += conn.recv(length - len(encrypted))

    decrypted = xor_bytes(encrypted, enc_key)

    # Last 2 bytes are HMAC(16-bit)
    if len(decrypted) < 2:
        print("SERVER: Invalid payload (too short).")
        return

    message = decrypted[:-2]
    hmac_received = int.from_bytes(decrypted[-2:], "big")
    hmac_expected = compute_hmac(message, mac_key)

    print("SERVER: HMAC received =", hmac_received)
    print("SERVER: HMAC expected =", hmac_expected)

    if hmac_received == hmac_expected:
        print("SERVER: VALID MESSAGE ->", message.decode(errors="replace"))
    else:
        print("SERVER: INVALID HMAC! Message rejected.")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    main()
