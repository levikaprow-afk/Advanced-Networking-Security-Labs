import socket
import select
import msvcrt
import protocol
# NAME <name> will set name. Server will reply error if duplicate
# GET_NAMES will get all names
# MSG <NAME> <message> will send message to client name
# EXIT will close client

my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect(("127.0.0.1", 2222))
print("Choose a command\n")
msg = ""
current_input = ""  # ➜ what the user is typing right now
print("> ", end="", flush=True)

while msg != "EXIT":
    rlist, wlist, xlist = select.select([my_socket], [], [], 0.1)
    if rlist:
        server_msg = protocol.get_message(my_socket)
        if server_msg == "":
            # server closed the connection"
            print("\nServer closed connection.")
            break

        # prints the received message and re-displays the prompt
        print("\r" + server_msg)
        print("> " + current_input, end="", flush=True)

    # 2) Check if the user pressed any key (without blocking)
    if msvcrt.kbhit():
         ch = msvcrt.getch()  # reads 1 key (in bytes)

        # ENTER → finishes the command
         if ch in (b'\r', b'\n'):
            print()  # skips a line
            msg = current_input.strip()  # updates the variable msg that controls the while loop

            if msg != "":
                # pack it with the protocol and send it to the server
                packet = protocol.create_msg(msg)
                my_socket.send(packet)

            # if the command was EXIT, we will exit the loop
            if msg.upper() == "EXIT":
                break

            # clears what was being typed and shows a new prompt
            current_input = ""
            print("> ", end="", flush=True)

        # BACKSPACE → deletes the last character
         elif ch == b'\x08':
            if len(current_input) > 0:
                current_input = current_input[:-1]
                # visually erase it in the console
                print("\b \b", end="", flush=True)

        # any other character → add it to current_input
         else:
            try:
                c = ch.decode('utf-8')
            except UnicodeDecodeError:
                c = ""
            if c:
                current_input += c
                print(c, end="", flush=True)

my_socket.close()

