import protocol  # Now the server can use protocol.get_message() and protocol.create_msg()
import socket
import select

SERVER_IP = "0.0.0.0"   # the server will accept any connection on port 2222
SERVER_PORT = 2222

# block dictionary: blocks[blocker] = set({blocked_user, ...})
blocks = {}


def get_name_by_socket(clients_names, sock):
    """
    clients_names contains the name and socket;
    Returns the name associated with a socket, or None if not found.
    """
    for name, s in clients_names.items():
        if s == sock:
            return name
    return None


def handle_client_request(current_socket, clients_names, data):
    """
    Lida com um comando de um cliente.
    Retorna (resposta_string, dest_socket ou 'BROADCAST' ou current_socket).
    """
    global blocks   # blocks its a global variable

    parts = data.split()
    if not parts:
        return "ERROR empty command", current_socket

    command = parts[0].upper() # if the user types in lowercase, we fix it

    # 1) NAME <name>
    if command == "NAME":
        if len(parts) != 2:
            return "ERROR bad NAME command", current_socket

        new_name = parts[1]

        # forbidden name
        if new_name.upper() == "BROADCAST":
            return "ERROR name unavailable", current_socket

        # name already exists
        if new_name in clients_names:
            return "ERROR name exists", current_socket

        # remove old name if it already existed
        old_name = get_name_by_socket(clients_names, current_socket)
        if old_name is not None:
            clients_names.pop(old_name)

        clients_names[new_name] = current_socket
        return f"HELLO {new_name}", current_socket

    # 2) GET_NAMES
    elif command == "GET_NAMES":
        names = " ".join(clients_names.keys())
        return "NAMES " + names, current_socket

    # 3) MSG <DEST> <mensagem>
    elif command == "MSG":
        if len(parts) < 3:
            return "ERROR bad MSG format", current_socket

        sender = get_name_by_socket(clients_names, current_socket)
        if sender is None:
            return "ERROR you must set NAME first", current_socket

        dest = parts[1]
        message = " ".join(parts[2:]) # take only the message
        full_message = f"{sender}: {message}"

        # BROADCAST
        if dest.upper() == "BROADCAST":
            # signals to the main that it is a broadcast
            return full_message, "BROADCAST"

        # private message
        if dest not in clients_names:
            return "ERROR user not found", current_socket

        # if the receiver has blocked the sender
        if dest in blocks and sender in blocks[dest]:
            return "ERROR you are blocked", current_socket

        dest_socket = clients_names[dest]
        return full_message, dest_socket

    # 4) BLOCK <name>
    elif command == "BLOCK":
        if len(parts) != 2:
            return "ERROR bad BLOCK format", current_socket

        blocked = parts[1]
        blocker = get_name_by_socket(clients_names, current_socket)

        if blocker is None:
            return "ERROR set NAME first", current_socket

        if blocker not in blocks:
            blocks[blocker] = set()

        blocks[blocker].add(blocked)
        return f"OK blocked {blocked}", current_socket

    # 5) EXIT
    elif command == "EXIT":
        # the main is the one that will close the socke
        return "EXIT", current_socket

    # unknown command
    else:
        return "ERROR unknown command", current_socket


def print_client_sockets(client_sockets):
    for c in client_sockets:
        print("\t", c.getpeername())


def main():
    print("server is up") 
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen()
    print("Listening for clients...")
    client_sockets = []
    messages_to_send = []
    clients_names = {}

    while True:
        read_list = client_sockets + [server_socket]
        ready_to_read, ready_to_write, in_error = select.select(read_list, client_sockets, [])
        for current_socket in ready_to_read:
            if current_socket is server_socket:
                client_socket, client_address = server_socket.accept()
                print("Client joined!\n", client_address)
                client_sockets.append(client_socket)
                print_client_sockets(client_sockets)
            else:
                print("Data from client\n")
                data = protocol.get_message(current_socket)
                if data == "":
                    # connection closed forcibly (window closed, etc.)
                    print("Connection closed\n")
                    sender_name = get_name_by_socket(clients_names, current_socket)
                    if sender_name is not None:
                        clients_names.pop(sender_name)
                    if current_socket in client_sockets:
                        client_sockets.remove(current_socket)
                    current_socket.close()
                    continue
                else:
                    print(data)
                    (response, dest_socket) = handle_client_request(current_socket, clients_names, data)

                    # if it was EXIT – remove the client cleanly
                    if response == "EXIT":
                        print("Client sent EXIT\n")
                        sender_name = get_name_by_socket(clients_names, current_socket)
                        if sender_name is not None:
                            clients_names.pop(sender_name)
                        if current_socket in client_sockets:
                            client_sockets.remove(current_socket)
                        current_socket.close()
                        continue

                    # BROADCAST: queue it for everyone
                    if dest_socket == "BROADCAST":
                        # who is sending (to respect BLOCK in the broadcast)
                        sender = response.split(":", 1)[0]
                        for sock in client_sockets:
                            dest_name = get_name_by_socket(clients_names, sock)
                            if dest_name is None:
                                continue
                            # if this recipient has blocked the sender → skip
                            if dest_name in blocks and sender in blocks[dest_name]:
                                continue
                            messages_to_send.append((sock, response))
                    else:
                        # normal message
                        messages_to_send.append((dest_socket, response))

        # write to everyone (note: only ones which are free to read...)
        for message in messages_to_send[:]:  # we copy the list because we are going to remove items
            current_socket, data = message
            if current_socket in ready_to_write:
                response = protocol.create_msg(data)
                current_socket.send(response)
                messages_to_send.remove(message)


if __name__ == '__main__':
    main()
