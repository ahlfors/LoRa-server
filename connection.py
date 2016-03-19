import threading
import socket
import warnings
import logging
import errno
from multiprocessing import Queue
import struct
import json

PROTOCOL_VERSION = 1
PUSH_DATA_ID = 0
PUSH_ACK_ID = 1
PULL_DATA_ID = 2
PULL_ACK_ID = 4
PULL_RESP_ID = 3

SEND_QUEUE_MAX_SIZE = 128

'''
Listen on a specific port for incoming connection. Once a connection is
established, call connHandler to handle the new connection. Typically, there
should be one Upstream instance and a Downstream instance of this class.
'''
class ConnectionAcceptor:
    def __init__(self, host, port, connHandler):
        self.connHandler = connHandler

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Get rid of the "address already in use" error
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))

        self.thread = threading.Thread(name='ConnAcceptor:'+str(port),
                                       target=self.mainLoop)

    def startListening(self):
        self.sock.listen(1)
        self.thread.start()
        return self.thread

    def mainLoop(self):
        while True:
            client_conn, client_addr = self.sock.accept()
            # spawn a thread to handle the newly established connection
            self.connHandler(client_conn, client_addr)

'''
This class provides the connection handler to be used by ConnectionAcceptor. In 
the handler it spawns a new thread to handle all the network transaction and
LoRaMac processing.
'''
class UpstreamWorkerPool:
    def __init__(self, loraMacProcessor):
        self.loraMacProcessor = loraMacProcessor

    def handleNewConnection(self, conn, addr):
        worker = PushDataWorker(conn, addr, self.loraMacProcessor)
        logging.info("[Upstream] Connected to %s:%d"%(addr[0],addr[1]))
        worker.start()

'''
This class provides the connection handler to be used by ConnectionAcceptor.
'''
class DownstreamWorkerPool:
    def __init__(self):
        self.onGwAvailable = None
        self.onGwDisconnected = None
        self.pullRespThreadPool = {}
        self.gwMacToTempName = {}

    def setGwChangeCallback(self, onGwAvailable, onGwDisconnected):
        self.onGwAvailable = onGwAvailable
        self.onGwDisconnected = onGwDisconnected

    def makeGwTempName(self, connAddr):
        return "%s:%d"%(connAddr[0],connAddr[1]) # temp name is src_ip:port

    def handleNewConnection(self, conn, addr):
        pdWorker = PullDataWorker(conn, addr, self.onGwMacAvailable, self.onClose)
        prWorker = PullRespWorker(conn, addr)
        
        # Store a gateway->worker mapping
        gwTempName = self.makeGwTempName(addr)
        self.pullRespThreadPool[gwTempName] = prWorker

        logging.info("[Downstream] Connected to %s"%gwTempName)

        pdWorker.start()
        prWorker.start()

    def sendToGateway(self, macAddr, jsonPayload):
        if macAddr not in self.gwMacToTempName:
            logging.error("[Downstream] Send failed. Gateway MAC address not yet available.")
            return errno.ENONET

        # Invoke the pullResp worker thread to send the data
        return self.pullRespThreadPool[self.gwMacToTempName[macAddr]].sendAsync(macAddr, jsonPayload)

    def onGwMacAvailable(self, connAddr, macAddr):
        self.gwMacToTempName[macAddr] = self.makeGwTempName(connAddr)
        # Tell LoRaMac that a new gateway is online
        if self.onGwAvailable != None:
            self.onGwAvailable(macAddr)

    def onClose(self, macAddr):
        logging.debug("[Downstream] Connection to gateway %s is down"%macAddr)

        # delete the mapping entry
        if macAddr in self.gwMacToTempName:
            del self.pullRespThreadPool[self.gwMacToTempName[macAddr]]
            del self.gwMacToTempName[macAddr]

        # Tell LoRaMac that a gateway is down
        if self.onGwDisconnected != None:
            self.onGwDisconnected(macAddr)

class PushDataWorker(threading.Thread):
    def __init__(self, conn, addr, loraMacProcessor):
        threading.Thread.__init__(self)

        self.conn = conn
        self.addr = addr
        self.loraMacProcessor = loraMacProcessor
        self.macAddr = 0

    def parsePushDataMsg(self, data):
        bytes = bytearray(data)

        if (len(bytes) >= 13 and
            bytes[0] == PROTOCOL_VERSION and
            bytes[3] == PUSH_DATA_ID):
            # Process token
            token = (bytes[1], bytes[2])

            # Process gateway MAC address
            mac_h = struct.unpack("<L", bytes[4:8])[0]
            mac_l = struct.unpack("<L", bytes[8:12])[0]
            macAddr = (mac_h << 32 | mac_l)
            # If macAddr does not equal to the macAddr that this thread
            # belongs to, then we have a serious problem..
            if (self.macAddr != 0 and self.macAddr != macAddr):
                logging.warning("[Upstream] Got unexpected MAC address: %x. Expected %x."%(macAddr, self.macAddr))
                return None

            # Retrieve JSON payload
            jsonDict = json.loads(bytes[12:].decode())

            return (token,jsonDict["rxpk"])
        else:
            logging.warning("[Upstream] Got invalid PUSH_DATA packet")
            return None

    def run(self):
        pushAck = bytearray([PROTOCOL_VERSION, 0, 0, PUSH_ACK_ID])
        #try:
        while True:
            data = self.conn.recv(512)
            if len(data) == 0: break # peer has shutdown
            ret = self.parsePushDataMsg(data)

            # If the packet is valid. Send an ACK and then process the data.
            if ret != None:
                (token, rxpkList) = ret

                # Send ACK
                pushAck[1] = token[0]
                pushAck[2] = token[1]
                self.conn.sendall(pushAck)

                # process JSON object
                for rxpk in rxpkList:
                    self.loraMacProcessor.processRawRxPayload(self.macAddr, rxpk)
        #except Exception,e:
        #   print str(e)

        logging.warning("[Upstream] Lost connection to gateway %x"%self.macAddr)


class PullDataWorker(threading.Thread):
    def __init__(self, conn, addr, onGwMacAvailable, onClose):
        threading.Thread.__init__(self)

        self.conn = conn
        self.addr = addr
        self.onGwMacAvailable = onGwMacAvailable
        self.onClose = onClose
        self.macAddr = 0

    def parsePullDataMsg(self, data):
        bytes = bytearray(data)

        if (len(bytes) >= 12 and
            bytes[0] == PROTOCOL_VERSION and
            bytes[3] == PULL_DATA_ID):
            # Process token
            token = (bytes[1], bytes[2])

            # Process gateway MAC address
            mac_h = struct.unpack("<L", bytes[4:8])[0]
            mac_l = struct.unpack("<L", bytes[8:12])[0]
            macAddr = (mac_h << 32 | mac_l)
            if self.macAddr == 0:
                self.macAddr = macAddr
                # Report macAddr avaialble
                self.onGwMacAvailable(self.addr, self.macAddr)
            elif self.macAddr != macAddr:
                # If macAddr does not equal to the macAddr that this thread
                # belongs to, then we have a serious problem..
                logging.warning("[Downstream] Got unexpected MAC address: %x. Expected %x."%(macAddr, self.macAddr))
                return None

            return token
        else:
            logging.warning("[Downstream] Got invalid PULL_DATA packet")
            return None

    def run(self):
        pullAck = bytearray([PROTOCOL_VERSION, 0, 0, PULL_ACK_ID])
        try:
            while True:
                data = self.conn.recv(128)
                if len(data) == 0: break # peer has shutdown

                # If this is indeed a PULL_DATA packet, send PULL_ACK response
                token = self.parsePullDataMsg(data)
                if token != None:
                    pullAck[1] = token[0]
                    pullAck[2] = token[1]
                    self.conn.sendall(pullAck)
        except Exception,e:
            print str(e)
        
        logging.warning("[Downstream PULL_DATA] Lost connection to gateway %x"%self.macAddr)
        self.onClose(self.macAddr)

class PullRespWorker(threading.Thread):
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)

        self.conn = conn
        self.addr = addr
        self.sendQ = Queue(SEND_QUEUE_MAX_SIZE)

    def sendAsync(self, macAddr, jsonPayload):
        self.sendQ.put((macAddr, jsonPayload))

    def run(self):
        try:
            while True:
                # If send queue is not empty, send out JSON objects
                (macAddr, jsonPayload) = self.sendQ.get()

                # form the payload
                payload = bytearray([PROTOCOL_VERSION, 0, 0, PULL_RESP_ID])
                payload.extend(jsonPayload)

                logging.info('Sending payload of size %d to GW %x'%(len(payload),macAddr))

                self.conn.sendall(payload)
        except Exception,e:
            print str(e)

        logging.warning("[Downstream PULL_RESP] Lost connection to gateway")
