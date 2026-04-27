# protocol.py
# This file defines how the client and server send and receive messages.
# Message format:
# [4-byte length][message text in UTF-8]
#
# Example:
# text = "HELLO"
# bytes = b"0005HELLO"


LENGTH_FIELD_SIZE = 4  # let's use 4 digits for the size, e.g.: '0012'


def create_msg(data: str) -> bytes: # -> bytes this function will return in bytes

    # Transform the str in bytes
    encoded = data.encode('utf-8') 

    # take the length in bytes
    length = len(encoded)

    # transform the length to 4 digits always
    # ex: 5 -> "0005"
    length_str = str(length).zfill(LENGTH_FIELD_SIZE)

    # join: first the size (in bytes), then the content
    return length_str.encode('utf-8') + encoded


def recv_exact(sock, n: int) -> bytes:    # n = total number of bytes of the msg
    
    data = b""    # b" = empty
    while len(data) < n:
        chunk = sock.recv(n - len(data))   
        if chunk == b"":
            # close connection
            return b""
        data += chunk
    return data


def get_message(sock) -> str:
    
    # 1) read the size field (always 4 bytes)
    length_bytes = recv_exact(sock, LENGTH_FIELD_SIZE)
    if length_bytes == b"":
        # server/client closed the connection
        return ""

    # convert the 4-byte value into an integer
    length_str = length_bytes.decode('utf-8')
    length = int(length_str)

    # 2) read exactly 'length' bytes of content
    data_bytes = recv_exact(sock, length)
    return data_bytes.decode('utf-8')
