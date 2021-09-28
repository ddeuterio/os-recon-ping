import sys
import socket
import struct
import random
import re
import signal

ECHO_REQUEST = 8
ECHO_REPLY = 0
TIMEOUT = 2             #seconds
ICMP_HEADER_SIZE = 8    #bytes
IP_HEADER_SIZE = 20     #bytes
LINUX_UNIX_TTL = 64
WINDOWS_TTL = 128

class Ping:
    pSocket = None
    address = None
    __pType = None      #1 byte
    __pCode = 0         #1 byte
    __pChecksum = 0     #2 bytes
    __pId = None        #2 bytes
    __pSeqNumber = None #2 bytes

    def __init__(self, address, pType = ECHO_REQUEST):
        self.__pType = pType #1 byte
        self.address = address
    
    def identifyOS(self, ttl):
        if (ttl <= LINUX_UNIX_TTL):
            return 'Linux/Unix'
        elif (ttl <= WINDOWS_TTL):
            return 'Windows'
        else:
            return 'Unknown'
        
    def createChecksum (self, pType, pCode, pId, pSeqNumber):
        #function partially copied from https://gist.github.com/pklaus/856268/bfe1500ceb1f4d762f436db6df056912337e33cd
        try:
            pTmp = struct.pack('BBHHH', pType, pCode, 0, pId, pSeqNumber)
        except struct.error as e:
            raise Exception(e)
        sum = 0
        countTo = len(pTmp)
        count = 0
        while (count < countTo):
            sum += pTmp[count+1]*256 + pTmp[count]
            count += 2
        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)
        return (~sum) & (0xffff)

    def createId (self):
        self.__pId = random.randrange(0, 65536)

    def createSeqNumber(self):
        #TO-DO: control sequence number for more than one echo request
        self.__pSeqNumber = 1

    def createPacket (self):
        packet = None
        try:
            packet = struct.pack('BBHHH', self.__pType, self.__pCode, self.__pChecksum, self.__pId, self.__pSeqNumber)
        except struct.error as e:
            raise Exception (e)
        return packet

    def sendPacket (self):
        try:
            self.pSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.pSocket.settimeout(TIMEOUT)
            bytesSent = self.pSocket.sendto(self.createPacket(), (self.address, 1))
            #check bytes sent to validate it
        except OSError as e:
            raise Exception('Problem sending the packet: '+e.strerror)
        except TimeoutError as e:
            raise Exception('Timeout error on request')
        print('[*] Echo request has been sent to: '+self.address)

    def readResponse (self):
        try:
            pResp = self.pSocket.recv(ICMP_HEADER_SIZE+IP_HEADER_SIZE)
            pType, pCode, pChecksum, pId, pSeqNumber = struct.unpack('BBHHH', pResp[IP_HEADER_SIZE:len(pResp)])
            tmpCheck = self.createChecksum(pType, pCode, pId, pSeqNumber)
            if (pType != 0 or pCode != ECHO_REPLY or tmpCheck != pChecksum):
                raise Exception('Response is malformed')
            print('[*] Response have been received')
            ttl = int.from_bytes(pResp[8:9], 'big')
            print('[*] OS identified is: '+self.identifyOS(ttl))
        except OSError as e:
            raise Exception('Response problem')
        except TimeoutError as e:
            raise Exception('Timeout error on response')
        except Exception as e:
            raise Exception ('Unknown problem')
        finally:
            self.pSocket.close()
    
    def echo(self):
        print('\n') #cmd format
        self.createId()
        self.createSeqNumber()
        self.__pChecksum = self.createChecksum(self.__pType, self.__pCode, self.__pId, self.__pSeqNumber)
        self.createPacket()
        self.sendPacket()
        self.readResponse()
        print('\n') #cmd format

def sigIntHandler (recvSignal, frame):
    print('[-] CTRL+C used')
    print('[-] Program finished')

def printUsage():
    print('Ping usage: python icmp.py -d [address]')

def validateAddress(address):
    valAddress = re.fullmatch('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', address)
    if (valAddress == None):
        raise Exception('Invalid IP address')
    return True

def main():
    print(len(sys.argv))
    print(sys.argv)
    if (len(sys.argv) < 3 or sys.argv[1] != '-d'):
        printUsage()
    else:
        try:
            address = sys.argv[2]
            validateAddress(address)
            echo = Ping(address, ECHO_REQUEST)
            echo.echo()
        except Exception as e:
            print(e)
            print('\n')


if __name__ == "__main__":
    main()
    signal.signal(signal.SIGINT, sigIntHandler)