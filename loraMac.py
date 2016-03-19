from multiprocessing import Queue
import threading
import base64
from CryptoPlus.Cipher import python_AES # PyCryptoPlus
import random
import logging
import struct

DOWNLINK_QUEUE_MAX_SIZE = 32

class LoRaEndDevice:
    def __init__(self, appEUI, devEUI, appKeyStr):
        '''
        appEUI: application unique identifier as a 64-bit integer (big endian)
        devEUI: device unique identifier as a 64-bit integer (big endian)
        appKeyStr: 16-byte encryption secret key as a byte string
        '''
        ### RF parameters
        self.receiveDelay1_usec = 1000000
        self.joinAcceptDelay1_usec = 5000000
        self.joinAcceptDelay2_usec = 6000000

        ### internal variables
        self.devAddr = None
        self.appEUI = appEUI
        self.devEUI = devEUI
        self.appKeyStr = appKeyStr
        self.nwkSKeyStr = ''
        self.appSKeyStr = ''
        self.joined = False
        self.gateways = set()
        self.dlQueue = Queue(DOWNLINK_QUEUE_MAX_SIZE)
        self.lock = threading.Lock()

        self.logger = logging.getLogger("Dev(%x)"%devEUI)

    def lock(self):
        self.lock.acquire()

    def unlock(self):
        self.lock.release()

    def getRxWindowDelayUsec(self, rxWindow):
        if rxWindow == RX_WINDOW_1:
            return self.receiveDelay1_usec
        elif rxWindow == RX_WINDOW_2:
            # second RX window opens 1 sec after the first one
            return self.receiveDelay1_usec + 1000000
        elif rxWindow == JOIN_ACCEPT_WINDOW_1:
            return self.joinAcceptDelay1_usec
        elif rxWindow == JOIN_ACCEPT_WINDOW_2:
            return self.joinAcceptDelay2_usec
        else:
            self.logger.warn("Unexpected rxWindow parameter %d"%rxWindow)
            return self.receiveDelay1_usec

    def putDownlinkMsg(self, msg):
        if dev.joined:
            self.dlQueue.put(msg)

    def hasPendingDownlink(self):
        return not self.dlQueue.empty()

    def popDownlinkMsg(self):
        return self.dlQueue.get_nowait()

    def bindWithGateway(self, gateway, rssi):
        self.gateways.add(gateway)

    def getGatewayForDownlink(self):
        # for now, just arbitrarilly pick one gateway
        return next(iter(self.gateways))

RX_WINDOW_1 = 1
RX_WINDOW_2 = 2
JOIN_ACCEPT_WINDOW_1 = 3
JOIN_ACCEPT_WINDOW_2 = 4

MTYPE_JOIN_REQUEST = 0
MTYPE_JOIN_ACCEPT = 1
MTYPE_UNCONFIRMED_DATA_UP = 2
MTYPE_UNCONFIRMED_DATA_DOWN = 3
MTYPE_CONFIRMED_DATA_UP = 4
MTYPE_CONFIRMED_DATA_DOWN = 5
MTYPE_RFU = 6
MTYPE_PROPRIETARY = 7

MAJOR_VERSION_LORAWAN = 0

class LoRaMac:
    def __init__(self, networkID, sendToGatewayFn):
        self.networkID = networkID & 0x7F # 7-bit
        self.netID = self.networkID # 24-bit
        self.sendToGateway = sendToGatewayFn
        self.euiToDevMap = {}
        self.addrToDevMap = {}

        self.logger = logging.getLogger("LoRaMac")
        self.logger.setLevel(logging.INFO)

    def registerEndDevice(self, appEUI, devEUI, appKey):
        '''
        appEUI: application unique identifier. 64-bit integer or an Int list
                of length 8 (little endian)
        devEUI: device unique identifier. 64-bit integer or an Int list
                of length 8 (little endian)
        appKey: 16-byte encryption secret key as a byte string or an Int list
                of length 16.
        '''
        if type(appEUI) != int:
            if type(appEUI) == list and len(appEUI) == 8:
                appEUI_int = struct.unpack(">Q",bytearray(appEUI))[0]
            else:
                raise Exception("EUI must be an integer or an int list with " \
                                "length 8 (big endian).")
        else:
            appEUI_int = appEUI

        if type(devEUI) != int:
            if type(devEUI) == list and len(devEUI) == 8:
                devEUI_int = struct.unpack(">Q",bytearray(devEUI))[0]
            else:
                raise Exception("EUI must be an integer or an int list with " \
                                "length 8 (big endian).")
        else:
            devEUI_int = devEUI

        if type(appKey) != str:
            if type(appKey) == list and len(appKey) == 16:
                appKeyStr = str(bytearray(appKey))
            else:
                raise Exception("AppKey must be a byte array or an int list " \
                                "with length 16.")
        else:
            appKeyStr = appKey

        self.euiToDevMap[(appEUI_int, devEUI_int)] = \
                                LoRaEndDevice(appEUI_int, devEUI_int, appKeyStr)

    def getDevFromEUI(self, appEUI, devEUI):
        if (appEUI, devEUI) in self.euiToDevMap:
            return self.euiToDevMap[(appEUI, devEUI)]
        else:
            return None

    def onGatewayOnline(self, macAddr):
        '''
        Callback to be used by the connection layer/module. Called when a gateway
        makes a connection to the server.
        '''
        self.logger.info("Gateway %x online"%macAddr)
        pass

    def onGatewayOffline(self, macAddr):
        '''
        Callback to be used by the connection layer/module. Called when a gateway
        disconnects from the server.
        '''
        self.logger.info("Gateway %x offline"%macAddr)
        pass

    def doDownlinkToDev(self, devAddr, eouTimestamp, rx1Freq, rx1Datarate,
                        rx1Codingrate):
        ## Get the end device object
        if devAddr in self.addrToDevMap:
            dev = self.addrToDevMap[devAddr]
        else:
            return -1

        # make the following ops atomic
        with dev.lock:

            if not dev.hasPendingDownlink():
                # nothing to do
                dev.unlock()
                return 0
            dlMsg = dev.popDownlinkMsg()

            ## Find out the time for the RX window
            delayUsec = dev.getRxWindowDelayUsec(dlMsg.rxWindow)
            dlTimestamp = eouTimestamp + int(delayUsec)

            ## Prepare the JSON payload
            jsonDict = {}
            # Receive window specific settings
            if (dlMsg.rxWindow == RX_WINDOW_1 or
                dlMsg.rxWindow == JOIN_ACCEPT_WINDOW_1):
                jsonDict["freq"] = rx1Freq
                jsonDict["datr"] = rx1Datarate
                jsonDict["codr"] = rx1Codingrate
            else:
                jsonDict["freq"] = dev.rx2Freq
                jsonDict["datr"] = dev.rx2Datarate
                jsonDict["codr"] = dev.rx2Codingrate
            # Settings not specific to receiving window
            jsonDict["tmst"] = dlTimestamp
            jsonDict["rfch"] = 0 # TODO: get this from the gateway object
            jsonDict["powe"] = 20 # TODO: magic number
            jsonDict["modu"] = dev.modulation
            jsonDict["ipol"] = dev.ipol
            jsonDict["prea"] = dev.numPreamble
            jsonDict["size"] = dlMsg.payloadSize
            jsonDict["data"] = dlMsg.payload
            payloadToGw = json.dumps({"txpk":jsonDict}, separators=(',',':'))
        

        # Send the JSON payload to the corresponding gateway
        gwMacAddr = dev.getGatewayForDownlink()
        self.sendToGateway(gwMacAddr, payloadToGw)

    def processRawRxPayload(self, gatewayMacAddr, jsonDict):
        '''
        Process the JSON payload received as part of the PUSH_DATA packet.
        This method should be supplied as a callback to the connection layer/module.

        gatewayMacAddr: MAC address of the source gateway
        jsonDict: resulting dictionary after JSON object has been parsed
        '''

        ### Process gateway metadata
        eouTimestamp = jsonDict["tmst"] # in usec
        upFreq = jsonDict["freq"]
        upDatarate = jsonDict["datr"]
        upCodingrate = jsonDict["codr"]
        upRssi = jsonDict["rssi"]

        self.logger.info("Got packet with tmst:%d freq:%f datarate:%s codr:%s" \
                         " rssi:%d"%(eouTimestamp, upFreq, upDatarate, 
                                     upCodingrate, upRssi))

        # decode padded Base64 RF packet
        phyPayload = bytearray(base64.b64decode(jsonDict["data"]))

        ### Process the PHY payload, whose structure is:
        ### | MHDR | MACPayload | MIC |
        mhdr = phyPayload[0]
        macPayload = phyPayload[1:-4]
        mic = phyPayload[-4:]
        
        # MHDR: | (7..5) MType | (4..2) RFU | (1..0) Major |
        mtype = (mhdr >> 5) & 0b111

        if mtype == MTYPE_JOIN_REQUEST:
            appEUI = struct.unpack("<Q", macPayload[0:8])[0] # little endian
            devEUI = struct.unpack("<Q", macPayload[8:16])[0] # little endian
            devNonce = struct.unpack("<H",macPayload[16:18])[0] # little endian

            dev = self.getDevFromEUI(appEUI, devEUI)
            if dev == None:
                # Either the message is corrupted or the device is not
                # registered on the server.
                return -1

            # Check message integrity (MIC)
            cmacWithAppKey = python_AES.new(dev.appKeyStr, python_AES.MODE_CMAC)
            if str(mic) != cmacWithAppKey.encrypt(phyPayload[:-4])[0:4]:
                # Bad MIC
                return -2

            # Handle join request. Should allocate a network address for the
            # device. Generate an AppNonce. Generate a join-accept message.
            # Also should update internal variables such as the mapping from
            # devAddr to device object 
            with dev.lock:
                self.handleJoinRequest(dev, devNonce, cmacWithAppKey)

        elif mtype == MTYPE_UNCONFIRMED_DATA_UP:
            # Process the MAC payload, whose structure is:
            # | FHDR | FPort | FRMPayload |
            # where FHDR is:
            # | DevAddr | FCtrl | FCnt | Fopts |
            pass
            #TODO: make sure the network ID in devAddr matches our network ID
        else:
            # Invalid MAC message type. Bail.
            return -1

        # Remember that this gateway has access to the device
        dev.bindWithGateway(gatewayMacAddr, rssi)

        # Signal that we have a downlink opportunity to this device
        self.doDownlinkToDev(devAddr, eouTimestamp, upFreq, upDatarate,
                             upCodingrate)

    def genDevAddr(self):
        ''' 
        Generates a random deviec address that is not yet in the network.

        devAddr == | 7-bit NetworkID | 25-bit NetworkAddress |
        '''
        while True:
            networkID_shifted = self.networkID << 25
            networkAddr = random.randint(0, (1<<25)-1)
            devAddr = networkID_shifted | networkAddr
            if devAddr not in self.addrToDevMap:
                break
            return devAddr

    def handleJoinRequest(self, dev, devNonce, cmacWithAppKey):
        if dev.joined:
            # [TODO]: check devNonce to prevent replay attacks
            # if devNonce is different than before, rejoin
            return

        devAddr = self.genDevAddr()
        self.addrToDevMap[devAddr] = dev
        dev.devAddr = devAddr
        appNonce = random.randint(0, (1<<24)-1)

        # derive the network session key and app session key
        aesWithAppKey = python_AES.new(dev.appKeyStr, python_AES.MODE_ECB)
        bufStr = str(bytearray([appNonce & 0xFF,
                                (appNonce >> 8) & 0xFF,
                                (appNonce >> 16) & 0xFF,
                                self.netID & 0xFF,
                                (self.netID >> 8) & 0xFF,
                                (self.netID >> 16) & 0xFF,
                                devNonce & 0xFF,
                                (devNonce >> 8) & 0xFF,
                                0,0,0,0,0,0,0]))
        dev.nwkSKeyStr = aesWithAppKey.encrypt(str(bytearray[0x01]) + bufStr)
        dev.appSKeyStr = aesWithAppKey.encrypt(str(bytearray[0x02]) + bufStr)

        # compose the join-accept message
        payloadNoMic = str(bytearray([(MTYPE_JOIN_ACCEPT << 5) | 
                                      MAJOR_VERSION_LORAWAN, # MAC header
                                      appNonce & 0xFF,
                                      (appNonce >> 8) & 0xFF,
                                      (appNonce >> 16) & 0xFF,
                                      self.netID & 0xFF,
                                      (self.netID >> 8) & 0xFF,
                                      (self.netID >> 16) & 0xFF,
                                      devAddr & 0xFF,
                                      (devAddr >> 8) & 0xFF,
                                      (devAddr >> 16) & 0xFF,
                                      (devAddr >> 24) & 0xFF,
                                      0, # DLSettings
                                      0, # RxDelay
                                     ]))
        mic = cmacWithAppKey.encrypt(payloadNoMic)[0:4]

        # encrypt the payload (not including MAC header and MIC)
        payloadEncrypted = aesWithAppKey.decrypt(payloadNoMic[1:])

        # Final payload (with MAC header and MIC at the end)
        payload = payloadNoMic[0] + payloadEncrypted + mic
        dlMsg = DownlinkMessage(payload, JOIN_ACCEPT_WINDOW_1)

        # Queue the downlink. Will be picked up by doDownlinkToDev()
        dev.joined = True
        dev.putDownlinkMsg(dlMsg)

class DownlinkMessage:
    def __init__(self, payload, rxWindow):
        self.payload = payload
        self.payloadSize = len(payload)
        self.rxWindow = rxWindow