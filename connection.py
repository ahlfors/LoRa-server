import socket
import threading
import logging
import errno
import Queue
import struct
import json
import sys
import select

PROTOCOL_VERSION = 1
PUSH_DATA_ID = 0
PUSH_ACK_ID = 1
PULL_DATA_ID = 2
PULL_ACK_ID = 4
PULL_RESP_ID = 3

SEND_QUEUE_MAX_SIZE = 128
POLL_INTERVAL_SEC = 1

def _eintr_retry(func, *args):
    """restart a system call interrupted by EINTR"""
    while True:
        try:
            return func(*args)
        except (OSError, select.error) as e:
            if e.args[0] != errno.EINTR:
                raise

class ConnectionManagerUDP:
    def __init__(self, host, portUp, portDown, processGatewayPacketFn,
                 onGatewayOnline=None, onGatewayOffline=None):
        if portUp == portDown:
            print "Error: Upstream port must be different from downstream port."
            sys.exit(-1)

        self.sockUp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockUp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sockUp.bind((host, portUp))

        self.sockDown = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockDown.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sockDown.bind((host, portDown))

        self.exitFlag = False
        logging.basicConfig()
        self.queueDown = Queue.Queue(SEND_QUEUE_MAX_SIZE)
        self.upHandler = UpstreamHandler(processGatewayPacketFn)
        self.downHandler = DownstreamHandler(self.queueDown)
        self.threadIn = threading.Thread(name='inboundThread', 
                                         target=self._inboundLoop)
        self.threadOut = threading.Thread(name='outboundThread', 
                                          target=self._outboundLoop)

    def startServing(self):
        self.threadOut.start()
        self.threadIn.start()

    def sendToGateway(self, macAddr, jsonPayload):
        self.downHandler.sendToGateway(macAddr, jsonPayload)

    def shutdown(self):
        self.exitFlag = True
        self.downHandler.shutdown()
        self.upHandler.shutdown()

    def _inboundLoop(self):
        while True:
            r, w, e = _eintr_retry(select.select, [self.sockUp, self.sockDown], 
                                   [], [], POLL_INTERVAL_SEC)

            if self.exitFlag:
                break

            # Handle the PUSH_DATA request and send PUSH_ACK right away
            if self.sockUp in r:
                data, addr = self.sockUp.recvfrom(1024)
                ack = self.upHandler.handlePushData(data, addr)
                if ack != None:
                    self.sockUp.sendto(ack, addr)

            # Handle the PULL_DATA request and queue PULL_ACK to the downstream
            # queue.
            if self.sockDown in r:
                data, addr = self.sockDown.recvfrom(128)
                self.downHandler.handlePullData(data, addr)

    def _outboundLoop(self):
        while True:
            try:
                data, addr = self.queueDown.get(block=True, 
                                                timeout=POLL_INTERVAL_SEC)
                self.sockDown.sendto(data, addr)
            except Queue.Empty:
                pass

            # check for termination
            if self.exitFlag:
                break

class DownstreamHandler:
    def __init__(self, queueDown):
        self.queueDown = queueDown
        self.queue = Queue.Queue(5)
        self.gwMacToAddrMap = {}
        self.pullAckPacket = bytearray([PROTOCOL_VERSION, 0, 0, PULL_ACK_ID])

        self.exitFlag = False
        self.logger = logging.getLogger("DownstreamHandler")
        self.logger.setLevel(logging.INFO)
        self.pullDataAckThread = threading.Thread(name='PullDataAck',
                                                  target=self._pullDataAckLoop)
        self.pullDataAckThread.start()

    def sendToGateway(self, macAddr, jsonPayload):
        # Determine the internet address of the gateway
        if macAddr not in self.gwMacToAddrMap:
            self.logger.error("[Downstream] Send failed. Gateway %x not " \
                              "connected."%macAddr)
            return errno.ENONET
        else:
            udpAddr = self.gwMacToAddrMap[macAddr]

        # form the payload and send it
        payload = bytearray([PROTOCOL_VERSION, 0, 0, PULL_RESP_ID])
        payload.extend(jsonPayload)
        self.queueDown.put((payload, udpAddr))

    def shutdown(self):
        self.exitFlag = True
        self.pullDataAckThread.join()

    def handlePullData(self, data, addr):
        # Defer the ACk generation to the thread loop
        try:
            self.queue.put_nowait((data,addr))
        except Queue.Full:
            self.logger.warning("PullDataAckThread queue is full. Dropping " \
                                "PULL_DATA request.")

    def _pullDataAckLoop(self):
        while True:
            try:
                data, addr = self.queue.get(block=True, 
                                            timeout=POLL_INTERVAL_SEC)
                result = self._parsePullDataMsg(data)
                if result != None:
                    (token, macAddr) = result

                    # verify MAC address
                    if macAddr not in self.gwMacToAddrMap:
                        self.gwMacToAddrMap[macAddr] = addr
                    elif addr != self.gwMacToAddrMap[macAddr]:
                        self.logger.warning("Gateway %x appears to have " \
                                            "changed internet address from " \
                                            "%s:%d to %s:%d"%(macAddr,
                                             self.gwMacToAddrMap[macAddr][0],
                                             self.gwMacToAddrMap[macAddr][1],
                                             addr[0], addr[1]))
                        # overwrite the old internet address
                        self.gwMacToAddrMap[macAddr] = addr

                    # TODO: refresh the timer associated with this MAC addr.
                    # The timer is used to determine whether a gateway
                    # connection is dead (If a gateway does not send PULL_DATA
                    # for a certain amount of time, just consider it dead).
                    pass

                    # compose and send the PULL_ACK packet
                    self.pullAckPacket[1] = token[0]
                    self.pullAckPacket[2] = token[1]
                    self.queueDown.put((self.pullAckPacket,addr))

            except Queue.Empty:
                pass

            # check for termination
            if self.exitFlag:
                break

    def _parsePullDataMsg(self, data):
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

            return (token, macAddr)
        else:
            self.logger.warning("Got invalid PULL_DATA packet.")
            return None

class UpstreamHandler:
    def __init__(self, processGatewayPacketFn):
        self.processGatewayPacketFn = processGatewayPacketFn
        self.workerPool = {}

    def handlePushData(self, data, addr):
        if addr not in self.workerPool:
            # Assume we have a new gateway connection. Make a new thread to
            # serve this gateway.
            worker = PushDataWorker(addr, self.processGatewayPacketFn)
            self.workerPool[addr] = worker
            worker.start()

        handler = self.workerPool[addr]
        return handler.handle_noblock(data, addr)

    def shutdown(self):
        for addr in self.workerPool:
            self.workerPool[addr].setExitFlag()

        for addr in self.workerPool:
            self.workerPool[addr].join()

class PushDataWorker(threading.Thread):
    def __init__(self, addr, processGatewayPacketFn):
        threading.Thread.__init__(self)

        self.sockAddr = addr
        self.processGatewayPacket = processGatewayPacketFn
        self.queue = Queue.Queue(16)
        self.pushAckPacket = bytearray([PROTOCOL_VERSION, 0, 0, PUSH_ACK_ID])
        self.macAddr = None
        self.logger = logging.getLogger("PushDataWorker(%s:%d)"%(addr[0],
                                                                 addr[1]))
        self.logger.setLevel(logging.INFO)
        self.exitFlag = False

    def handle_noblock(self, data ,addr):
        if addr != self.sockAddr:
            self.logger.warning("Socket address mismatch. Dropping PushData " \
                                "request.")
            return None
        
        result = self._parsePushDataMsg(data)
        if result != None:
            (token, rxpkList) = result

            # Defer the actual processing to the worker thread
            try:
                self.queue.put_nowait(rxpkList)
            except Queue.Full:
                self.logger.warning("PushDataWorker queue is full. Dropping " \
                                    "PushData request.")
                return None

            # compose and return the PUSH_ACK packet
            self.pushAckPacket[1] = token[0]
            self.pushAckPacket[2] = token[1]
            return self.pushAckPacket
        else:
            self.logger.info("Got invalid PUSH_DATA packet. Dropped.")
            return None
    
    def run(self):
        while True:
            try:
                rxpkList = self.queue.get(block=True, timeout=POLL_INTERVAL_SEC)
                # process JSON object
                for rxpk in rxpkList:
                    self.processGatewayPacket(self.macAddr, rxpk)
            except Queue.Empty:
                pass

            # check for termination
            if self.exitFlag:
                break

    def setExitFlag(self):
        self.exitFlag = True

    def _parsePushDataMsg(self, data):
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
            if (self.macAddr == None):
                self.macAddr = macAddr
            elif (self.macAddr != macAddr):
                self.logger.warning("Got unexpected MAC address: " \
                                    "%x. Expected %x."%(macAddr, self.macAddr))
                return None

            # Retrieve JSON payload
            jsonDict = json.loads(bytes[12:].decode())

            return (token,jsonDict["rxpk"])
        else:
            return None
