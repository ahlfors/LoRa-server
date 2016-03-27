from multiprocessing import Queue
import threading
import base64
from CryptoPlus.Cipher import python_AES # PyCryptoPlus
import random
import logging
import struct
import json
from collections import deque
import math
import numpy

DOWNLINK_QUEUE_MAX_SIZE = 32
DEVNONCE_HISTORY_LEN = 5

class LoRaMacCrypto:
    CRYPTO_BLOCK_SIZE = 16

    def __init__(self, appKeyStr):
        self.appKeyStr = appKeyStr
        self.nwkSKeyStr = ''
        self.appSKeyStr = ''
        self.aesWithNwkSKey = None # Set during a device's join process
        self.aesWithAppSKey = None

    def setSessionKeys(self, nwkSKeyStr, appSKeyStr):
        # Create AES and CMAC objects that can be reused. But remember to reset
        # them after each encryption operation
        self.aesWithNwkSKey = python_AES.new(nwkSKeyStr, python_AES.MODE_ECB)
        self.aesWithAppSKey = python_AES.new(appSKeyStr, python_AES.MODE_ECB)
        #self.cmacWithNwkSKey = python_AES.new(nwkSKeyStr, python_AES.MODE_CMAC)
        self.nwkSKeyStr = nwkSKeyStr
        self.appSKeyStr = appSKeyStr

    def padToBlockSize(self, byteStr):
        # zero padding
        if len(byteStr) % self.CRYPTO_BLOCK_SIZE != 0:
            buf = byteStr + str(bytearray([0]* \
                                (self.CRYPTO_BLOCK_SIZE-len(byteStr))))
        else:
            buf = byteStr

        assert(len(buf) % self.CRYPTO_BLOCK_SIZE == 0)
        return buf

    def computeJoinMic(self, byteStr):
        '''
        byteStr is everything in the PHYPayload except MIC
        secret key is AppKey

        LoRaWAN Specification v1.0 Ch6.2.4 and Ch6.2.5
        '''
        # no padding is needed
        cmacWithAppKey = python_AES.new(self.appKeyStr, python_AES.MODE_CMAC)
        return cmacWithAppKey.encrypt(byteStr)[:4]

    def encryptJoinAccept(self, byteStr):
        '''
        byteStr is | AppNonce | NetID | DevAddr | RFU | RxDelay | CFList | MIC |
        secret key is AppKey

        LoRaWAN Specification v1.0 Ch6.2.5
        '''
        paddedBuf = self.padToBlockSize(byteStr)
        aesWithAppKey = python_AES.new(self.appKeyStr, python_AES.MODE_ECB)
        return aesWithAppKey.decrypt(paddedBuf) # DECRYPT here is on purpose

    def deriveSessionKey(self, byteStr):
        '''
        byteStr is | 0x01 or 0x02 | AppNonce | NetID | DevNonce | padding |
        secret key is AppKey

        LoRaWAN Specification v1.0 Ch6.2.5
        '''
        # Just to be certain that the buffer is padded
        paddedBuf = self.padToBlockSize(byteStr)
        aesWithAppKey = python_AES.new(self.appKeyStr, python_AES.MODE_ECB)
        return aesWithAppKey.encrypt(paddedBuf)

    def computeFrameMic(self, msgStr, updown, devAddr, seqCnt, msgLen):
        '''
        msg: | MHDR | FHDR | FPORT | FRMPAYLOAD |
        updown: 0 for UP_LINK and 1 for DOWN_LINK
        devAddr (uint32): 4-byte device address
        seqCnt (uint32): frame count
        msgLen (uint8): byte count of msg

        LoRaWAN Specification v1.0 Ch4.4
        '''
        # no padding is needed for CMAC. No finalizing needed either.
        byteStr = str(bytearray([0x49, 0, 0, 0, 0, updown,
                                 devAddr & 0xFF,
                                 (devAddr >> 8) & 0xFF,
                                 (devAddr >> 16) & 0xFF,
                                 (devAddr >> 24) & 0xFF,
                                 seqCnt & 0xFF,
                                 (seqCnt >> 8) & 0xFF,
                                 (seqCnt >> 16) & 0xFF,
                                 (seqCnt >> 24) & 0xFF,
                                 0, msgLen])) + msgStr
        cmacWithNwkSKey = python_AES.new(self.nwkSKeyStr, python_AES.MODE_CMAC)
        return cmacWithNwkSKey.encrypt(byteStr)[:4]

    def cipherCmdPayload(self, frmPayloadStr, updown, devAddr, seqCnt):
        return self.cipherPayload(self.aesWithNwkSKey, frmPayloadStr, updown,
                                  devAddr, seqCnt)

    def cipherDataPayload(self, frmPayloadStr, updown, devAddr, seqCnt):
        return self.cipherPayload(self.aesWithAppSKey, frmPayloadStr, updown,
                                  devAddr, seqCnt)

    def cipherPayload(self, aesWithKey, frmPayloadStr, updown, devAddr, seqCnt):
        '''
        aesWithKey: a cipher object from CryptoPlus
        frmPayloadStr: | FRMPayload |
        updown: 0 for UP_LINK and 1 for DOWN_LINK
        devAddr (uint32): 4-byte device address
        seqCnt (uint32): frame count

        LoRaWAN Specification v1.0 Ch4.3.3.1
        '''
        paddedPaylod = self.padToBlockSize(frmPayloadStr)
        k = int(math.ceil(len(frmPayloadStr) / 16.0))
        A = bytearray([1, 0, 0, 0, 0, updown, devAddr & 0xFF,
                       (devAddr >> 8) & 0xFF,
                       (devAddr >> 16) & 0xFF,
                       (devAddr >> 24) & 0xFF,
                       seqCnt & 0xFF,
                       (seqCnt >> 8) & 0xFF,
                       (seqCnt >> 16) & 0xFF,
                       (seqCnt >> 24) & 0xFF,
                       0, 0])

        S = ''
        aesWithKey.final() # clear the cipher's cache
        for i in xrange(1, k+1):
            A[15] = i
            S += aesWithKey.encrypt(str(A))
        aesWithKey.final() # clear the cipher's cache
        
        dtype = numpy.dtype('<Q8')
        ciphered = numpy.bitwise_xor(numpy.fromstring(paddedPaylod,dtype=dtype),
                                   numpy.fromstring(S,dtype=dtype)).tostring()
        return ciphered[:len(frmPayloadStr)]

class LoRaEndDevice:
    def __init__(self, appEUI, devEUI, appKeyStr):
        '''
        appEUI: application unique identifier as a 64-bit integer
        devEUI: device unique identifier as a 64-bit integer
        appKeyStr: 16-byte encryption secret key as a byte string
        '''
        ### RF parameters
        self.dlModulation = "LORA"
        self.dlIpol = True # LoRaWAN recommends downlink to use inverted pol
        self.dlNumPreamble = 8
        self.rx2FreqMHz = 923.300000
        self.rx2Datarate = "SF10BW500"
        self.rx2Codingrate = "4/5"
        self.receiveDelay1_usec = 1000000
        self.joinAcceptDelay1_usec = 5000000
        self.joinAcceptDelay2_usec = 6000000

        ### internal variables
        self.crypto = LoRaMacCrypto(appKeyStr)
        self.devAddr = None
        self.appEUI = appEUI
        self.devEUI = devEUI
        self.appKeyStr = appKeyStr
        self.nwkSKeyStr = '' # will be set in self.onJoin()
        self.appSKeyStr = '' # will be set in self.onJoin()
        self.joined = False
        self.devNonceHistory = deque(maxlen=DEVNONCE_HISTORY_LEN)
        self.upSeqCnt_u32 = 0
        self.downSeqCnt_u32 = 0
        self.gateways = set()
        self.appPendingDownlink = Queue(DOWNLINK_QUEUE_MAX_SIZE)
        self.macPendingDownlink = Queue(DOWNLINK_QUEUE_MAX_SIZE)
        self.dlQueue = deque(maxlen=DOWNLINK_QUEUE_MAX_SIZE)
        self.lock = threading.RLock()

        self.logger = logging.getLogger("Dev(%x)"%devEUI)
        self.logger.setLevel(logging.INFO)

    #def lock(self):
    #    self.lock.acquire()

    #def unlock(self):
    #    self.lock.release()
    
    def onNewUplinkData(self, fPort, data):
        self.logger.info("[Uplink Received] fPort:%d data:%s"%(fPort, 
                                                               str(data)))

    def canJoin(self, devNonce):
        return devNonce not in self.devNonceHistory

    def onJoin(self, newDevAddr, appNonce, devNonce, netID):
        # Reset internal variables
        self.joined = True
        self.upSeqCnt_u32 = 0
        self.downSeqCnt_u32 = 0
        self.devAddr = newDevAddr
        self.devNonceHistory.append(devNonce)

        # derive the network session key and app session key
        bufStr = str(bytearray([appNonce & 0xFF,
                                (appNonce >> 8) & 0xFF,
                                (appNonce >> 16) & 0xFF,
                                netID & 0xFF,
                                (netID >> 8) & 0xFF,
                                (netID >> 16) & 0xFF,
                                devNonce & 0xFF,
                                (devNonce >> 8) & 0xFF,
                                0,0,0,0,0,0,0]))
        self.nwkSKeyStr = self.crypto.deriveSessionKey(str(bytearray([0x01])) +\
                                                       bufStr)
        self.appSKeyStr = self.crypto.deriveSessionKey(str(bytearray([0x02])) +\
                                                       bufStr)
        self.crypto.setSessionKeys(self.nwkSKeyStr, self.appSKeyStr)
        self.logger.info("NwkSKey: %s"%self.nwkSKeyStr.encode('hex'))
        self.logger.info("AppSKey: %s"%self.appSKeyStr.encode('hex'))

        # compose the join-accept message
        mhdr = str(bytearray([MTYPE_JOIN_ACCEPT_MASK | \
                              MAJOR_VERSION_LORAWAN]))
        payload = str(bytearray([ appNonce & 0xFF,
                                  (appNonce >> 8) & 0xFF,
                                  (appNonce >> 16) & 0xFF,
                                  netID & 0xFF,
                                  (netID >> 8) & 0xFF,
                                  (netID >> 16) & 0xFF,
                                  newDevAddr & 0xFF,
                                  (newDevAddr >> 8) & 0xFF,
                                  (newDevAddr >> 16) & 0xFF,
                                  (newDevAddr >> 24) & 0xFF,
                                  0, # DLSettings
                                  0, # RxDelay
                                ]))
        mic = self.crypto.computeJoinMic(mhdr + payload)

        # encrypt the payload (not including MAC header)
        bodyEncrypted = self.crypto.encryptJoinAccept(payload + mic)

        # Queue the downlink. Will be picked up by LoRaMac.doDownlinkToDev()
        dlMsg = DownlinkMessage(mhdr + bodyEncrypted, JOIN_ACCEPT_WINDOW_1)
        self.putDownlinkMsg(dlMsg)
        self.logger.info("Join accept msg downlink queued")

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
        with self.lock:
            self.dlQueue.append(msg)

    def hasPendingDownlink(self):
        return len(self.dlQueue) != 0

    def popDownlinkMsg(self):
        with self.lock:
            return self.dlQueue.popleft()

    def bindWithGateway(self, gatewayMacAddr, rssi):
        self.gateways.add(gatewayMacAddr)

    def getGatewayForDownlink(self):
        # for now, just arbitrarilly pick one gateway
        return next(iter(self.gateways))

RX_WINDOW_1 = 1
RX_WINDOW_2 = 2
JOIN_ACCEPT_WINDOW_1 = 3
JOIN_ACCEPT_WINDOW_2 = 4

UP_LINK = 0
DOWN_LINK = 1

MTYPE_JOIN_REQUEST_MASK          = 0b00000000
MTYPE_JOIN_ACCEPT_MASK           = 0b00100000
MTYPE_UNCONFIRMED_DATA_UP_MASK   = 0b01000000
MTYPE_UNCONFIRMED_DATA_DOWN_MASK = 0b01100000
MTYPE_CONFIRMED_DATA_UP_MASK     = 0b10000000
MTYPE_CONFIRMED_DATA_DOWN_MASK   = 0b10100000
MTYPE_RFU_MASK                   = 0b11000000
MTYPE_PROPRIETARY_MASK           = 0b11100000

MAJOR_VERSION_LORAWAN = 0

FCTRL_FOPTS_LEN_MASK = 0b00001111
FCTRL_FPENDING_MASK  = 0b00010000
FCTRL_ACK_MASK       = 0b00100000
FCTRL_ADRACKREQ_MASK = 0b01000000
FCTRL_ADR_MASK       = 0b10000000

class LoRaMacServer:
    ### US902-928 Channel Frequencies
    UPSTREAM_BW125_LOWEST_FREQ_MHZ = 902.3
    UPSTREAM_BW125_SPACING_MHZ = 0.2
    UPSTREAM_BW125_NUM_CHAN = 64
    UPSTREAM_BW500_LOWEST_FREQ_MHZ = 903.0
    UPSTREAM_BW500_SPACING_MHZ = 1.6
    UPSTREAM_BW500_NUM_CHAN = 8
    DOWNSTREAM_BW500_LOWEST_FREQ_MHZ = 923.3
    DOWNSTREAM_BW500_SPACING_MHZ = 0.6
    DOWNSTREAM_BW500_NUM_CHAN = 8

    def __init__(self, networkID, sendToGatewayFn=None):
        self.networkID = networkID & 0x7F # 7-bit
        self.netID = self.networkID # 24-bit
        self.sendToGateway = sendToGatewayFn
        self.euiToDevMap = {}
        self.addrToDevMap = {}

        self.logger = logging.getLogger("LoRaMacServer")
        self.logger.setLevel(logging.INFO)

    def setGatewaySenderFn(self, fn):
        self.sendToGateway = fn

    def _EUI_int(self, EUI):
        if type(EUI) != int:
            if type(EUI) == list and len(EUI) == 8:
                return struct.unpack(">Q",bytearray(EUI))[0]
            else:
                raise Exception("EUI must be an integer or an int list with " \
                                "length 8 (big endian).")
        else:
            return EUI

    def registerEndDevice(self, appEUI, devEUI, appKey):
        '''
        appEUI: application unique identifier. 64-bit integer or an Int list
                of length 8 (little endian)
        devEUI: device unique identifier. 64-bit integer or an Int list
                of length 8 (little endian)
        appKey: 16-byte encryption secret key as a byte string or an Int list
                of length 16.
        '''
        appEUI_int = self._EUI_int(appEUI)
        devEUI_int = self._EUI_int(devEUI)

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

    def scheduleAppDownlink(self, appEUI, devEUI, appPort, appPayload,
                            ack=False):
        appEUI_int = self._EUI_int(appEUI)
        devEUI_int = self._EUI_int(devEUI)

        dev = self.getDevFromEUI(appEUI_int,devEUI_int)
        if dev == None or not dev.joined:
            self.logger.warn("Cannot send frame. Device not registered or not" \
                             " joined (appEUI %x devEUI %x)"%(appEUI_int,
                                                              devEUI_int))
            return -1

        with dev.lock:
            if dev.appPendingDownlink.full():
                self.logger.warn("Cannot send frame. Device downlink queue " \
                                 "full.")
                return -2
            dev.appPendingDownlink.put_nowait((appPort, appPayload, ack))

        return 0

    def scheduleMacCmdDownlink(self, dev, macCmdPayload):
        pass # TODO

    def prepareDownlinkMsg(self, dev):
        '''
        Return a DownlinkMessage object
        '''
        if len(dev.dlQueue) != 0:
            return dev.dlQueue.popleft()

        # Retrieve pending app data
        frmPayload = None
        if not dev.appPendingDownlink.empty():
            fPort, frmPayload, appAck = dev.appPendingDownlink.get_nowait()
            frmPayloadEncrypt = dev.crypto.cipherDataPayload(frmPayload,
                                                             DOWN_LINK,
                                                             dev.devAddr,
                                                             dev.downSeqCnt_u32)

        # Retrieve pending MAC commands
        fOpts = ''
        macAck = False
        if not dev.macPendingDownlink.empty():
            # if macCmdPayload > 15 bytes and we have no app downlink, use
            # FPort 0 and pack MAC commands into FRMPayload
            pass
            #noOp = False

        if frmPayload == None:
            # no op
            return None

        if dev.appPendingDownlink.empty() and dev.macPendingDownlink.empty():
            fPending = 0
        else:
            fPending = FCTRL_FPENDING_MASK
        
        if appAck or macAck:
            ack = FCTRL_ACK_MASK
            mhdr = chr(MTYPE_CONFIRMED_DATA_DOWN_MASK |
                       MAJOR_VERSION_LORAWAN)
        else:
            ack = 0
            mhdr = chr(MTYPE_UNCONFIRMED_DATA_DOWN_MASK |
                       MAJOR_VERSION_LORAWAN)

        # Pack the PHYPayload
        fCtrl = ack | fPending | (len(fOpts) & 0xF)
        fhdr = struct.pack("<L", dev.devAddr) + chr(fCtrl) + \
               struct.pack("<H", dev.downSeqCnt_u32 & 0xFFFF) + fOpts
        macHdrPayload = mhdr + fhdr + chr(fPort & 0xFF) + frmPayloadEncrypt
        mic = dev.crypto.computeFrameMic(macHdrPayload, DOWN_LINK, dev.devAddr,
                                         dev.downSeqCnt_u32, len(macHdrPayload))
        phyPayload = macHdrPayload + mic

        dev.downSeqCnt_u32 = (dev.downSeqCnt_u32 + 1) & 0xFFFFFFFF
        return DownlinkMessage(phyPayload, RX_WINDOW_1)

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

    def getUplinkChannelFromFreq(self, ulDatarate, ulFreqMHz):
        if "500" in ulDatarate:
            # BW500 channels
            return round((ulFreqMHz - self.UPSTREAM_BW500_LOWEST_FREQ_MHZ) / \
                         self.UPSTREAM_BW500_SPACING_MHZ) % \
                   self.UPSTREAM_BW500_NUM_CHAN
        else:
            # BW125 channels
            return round((ulFreqMHz - self.UPSTREAM_BW125_LOWEST_FREQ_MHZ) / \
                         self.UPSTREAM_BW125_SPACING_MHZ) % \
                   self.UPSTREAM_BW125_NUM_CHAN

    def getRxWindow1Freq(self, ulChannel):
        return self.DOWNSTREAM_BW500_LOWEST_FREQ_MHZ + \
               (ulChannel % self.DOWNSTREAM_BW500_NUM_CHAN) * \
               self.DOWNSTREAM_BW500_SPACING_MHZ

    def getRxWindow1DataRate(self, ulDatarate):
        # [TODO]: Take RX1DROffsest into account.
        # Right now just hard code
        assert(ulDatarate == 'SF10BW125') # uplink is DR0
        return 'SF10BW500' # downlink is DR10

    def doDownlinkToDev(self, dev, eouTimestamp, ulChannel, ulDatarate,
                        ulCodingrate):
        # make the following ops atomic
        with dev.lock:
            dlMsg = self.prepareDownlinkMsg(dev)
            if dlMsg == None:
                # nothing to do
                self.logger.info("[doDownlinkToDev] No queued downlink")
                return 0

            ## Find out the time for the RX window
            delayUsec = dev.getRxWindowDelayUsec(dlMsg.rxWindow)
            dlTimestamp = eouTimestamp + int(delayUsec)

            ## Prepare the JSON payload
            jsonDict = {}
            # Receive window specific settings
            if (dlMsg.rxWindow == RX_WINDOW_1 or
                dlMsg.rxWindow == JOIN_ACCEPT_WINDOW_1):
                jsonDict["freq"] = self.getRxWindow1Freq(ulChannel)
                jsonDict["datr"] = self.getRxWindow1DataRate(ulDatarate)
                jsonDict["codr"] = ulCodingrate
            else:
                jsonDict["freq"] = dev.rx2FreqMHz
                jsonDict["datr"] = dev.rx2Datarate
                jsonDict["codr"] = dev.rx2Codingrate
            # Settings not specific to receiving window
            jsonDict["tmst"] = dlTimestamp
            jsonDict["rfch"] = 0 # TODO: get this from the gateway object
            jsonDict["powe"] = 20 # TODO: magic number
            jsonDict["modu"] = dev.dlModulation
            jsonDict["ipol"] = dev.dlIpol
            #jsonDict["prea"] = dev.dlNumPreamble
            jsonDict["size"] = dlMsg.payloadSize
            jsonDict["data"] = dlMsg.payloadBase64
            payloadToGw = json.dumps({"txpk":jsonDict}, separators=(',',':'))

        # Send the JSON payload to the corresponding gateway
        gwMacAddr = dev.getGatewayForDownlink()
        self.logger.info("[doDownlinkToDev] Downlink to dev %x via gateway %x" \
                         " with RF params tmst:%d freq:%f datr:%s codr:%s " \
                         "plsize:%d"%(dev.devAddr, gwMacAddr, jsonDict["tmst"],\
                                      jsonDict["freq"], jsonDict["datr"], \
                                      jsonDict["codr"], jsonDict["size"]))
        if self.sendToGateway != None:
            self.sendToGateway(gwMacAddr, payloadToGw)
        else:
            self.logger.error("No sender function. Please call setGatewaySenderFn().")

    def processRawRxPayload(self, gatewayMacAddr, jsonDict):
        '''
        Process the JSON payload received as part of the PUSH_DATA packet.
        This method should be supplied as a callback to the connection layer/module.

        gatewayMacAddr: MAC address of the source gateway
        jsonDict: resulting dictionary after JSON object has been parsed
        '''

        ### Process gateway metadata
        eouTimestamp = jsonDict["tmst"] # in usec
        ulFreqMHz = jsonDict["freq"]
        ulDatarate = jsonDict["datr"]
        ulCodingrate = jsonDict["codr"]
        ulRssi = jsonDict["rssi"]
        ulChannel = self.getUplinkChannelFromFreq(ulDatarate, ulFreqMHz)

        self.logger.info("Got packet with tmst:%d freq:%f datarate:%s codr:%s" \
                         " rssi:%d"%(eouTimestamp, ulFreqMHz, ulDatarate, 
                                     ulCodingrate, ulRssi))

        # decode padded Base64 RF packet
        phyPayload = base64.b64decode(jsonDict["data"])

        ### Process the PHY payload, whose structure is:
        ### | MHDR | MACPayload | MIC |
        mhdrByte = ord(phyPayload[0])
        macPayload = phyPayload[1:-4]
        mic = phyPayload[-4:]
        
        # MHDR: | (7..5) MType | (4..2) RFU | (1..0) Major |
        mtype = mhdrByte & 0b11100000

        if mtype == MTYPE_JOIN_REQUEST_MASK:
            appEUI = struct.unpack("<Q", macPayload[0:8])[0] # little endian
            devEUI = struct.unpack("<Q", macPayload[8:16])[0]
            devNonce = struct.unpack("<H",macPayload[16:18])[0]

            dev = self.getDevFromEUI(appEUI, devEUI)
            if dev == None:
                # Either the message is corrupted or the device is not
                # registered on the server.
                self.logger.info("Cannot get device from EUI")
                return -1

            # Check message integrity (MIC)
            if mic != dev.crypto.computeJoinMic(phyPayload[:-4]):
                self.logger.info("Bad packet Message Integrity Code. " \
                                 "MType: %d"%mtype)
                return -2

            # Handle join request. Should allocate a network address for the
            # device. Generate an AppNonce. Generate a join-accept message.
            # Also should update internal variables such as the mapping from
            # devAddr to device object 
            with dev.lock:
                self.handleJoinRequest(dev, devNonce)

        elif (mtype == MTYPE_UNCONFIRMED_DATA_UP_MASK) or \
             (mtype == MTYPE_CONFIRMED_DATA_UP_MASK):
            # Process the MAC payload, whose structure is:
            # | FHDR | FPort | FRMPayload |
            # where FHDR is:
            # | DevAddr | FCtrl | FCnt | Fopts |

            devAddr = struct.unpack("<L", macPayload[0:4])[0] # little endian
            if devAddr not in self.addrToDevMap:
                self.logger.info("Device %x has not joined yet. Dropping " \
                                 "data frame."%devAddr)
                return -1

            dev = self.addrToDevMap[devAddr]

            # unpack frame header
            fCtrl = ord(macPayload[4])
            fOptsLen = fCtrl & FCTRL_FOPTS_LEN_MASK
            fPortIdx = 7 + fOptsLen
            upSeqCnt_u16 = struct.unpack("<H", macPayload[5:7])[0]

            # Correct the 16-bit frame counter for roll-over
            upSeqCntDiff = (upSeqCnt_u16 - (dev.upSeqCnt_u32 & 0xFFFF))
            if upSeqCntDiff >= 0:
                # naively assume there is no roll-ever
                upSeqCntTemp_u32 = dev.upSeqCnt_u32 + upSeqCntDiff
            else:
                # (naively) assume we have ONE 16-bit roll-over.
                upSeqCntTemp_u32 = dev.upSeqCnt_u32 + 0x10000 + upSeqCntDiff

            # Verify message integrity
            micCalc = dev.crypto.computeFrameMic(phyPayload[:-4], 
                                                 UP_LINK,
                                                 devAddr,
                                                 upSeqCntTemp_u32,
                                                 len(phyPayload[:-4]))

            if mic != micCalc:
                self.logger.info("Bad packet Message Integrity Code. " \
                                 "MType: %d"%mtype)
                return -2

            # Handle duplicate packets
            if (dev.upSeqCnt_u32 == upSeqCntTemp_u32) and \
               (dev.upSeqCnt_u32 != 0):
                # TODO: perform ACK to end-device
                return 0
            dev.upSeqCnt_u32 = upSeqCntTemp_u32

            if fCtrl & FCTRL_ACK_MASK:
                # TODO: this is an ACK from the end-device
                pass

            if fOptsLen > 0:
                # fOpts contains piggybacked MAC commands (unencrypted)
                self.processMacCommands(dev, macPayload[7:fPortIdx])

            # "If the frame payload field is not empty, the FPort field must
            # be present" (LoRaWAN specification v1.0 Ch4.3.2)
            if fPortIdx < len(macPayload):
                fPort = ord(macPayload[fPortIdx])
                frmPayload = macPayload[fPortIdx+1:]

                if fPort == 0:
                    # frmPayload carries MAC commands, encrypted using the
                    # network session key
                    data = dev.crypto.cipherCmdPayload(frmPayload, UP_LINK, 
                                                       devAddr,
                                                       dev.upSeqCnt_u32)
                    self.processMacCommands(dev, data)
                else:
                    data = dev.crypto.cipherDataPayload(frmPayload, UP_LINK, 
                                                        devAddr,
                                                        dev.upSeqCnt_u32)
                    dev.onNewUplinkData(fPort, data)

            #TODO: make sure the network ID in devAddr matches our network ID
        else:
            # Invalid MAC message type. Bail.
            self.logger.info("Got invalid MAC message type: %d"%mtype)
            return -1

        # Remember that this gateway has access to the device
        dev.bindWithGateway(gatewayMacAddr, ulRssi)

        # Signal that we have a downlink opportunity to this device
        self.doDownlinkToDev(dev, eouTimestamp, ulChannel, ulDatarate,
                             ulCodingrate)

        return 0

    def processMacCommands(self, dev, macCommands):
        print "Got MAC commands"

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

    def handleJoinRequest(self, dev, devNonce):
        # check devNonce to prevent replay attacks
        if not dev.canJoin(devNonce):
            self.logger.info("Replay attack detected. Dropping join request.")
            return

        if dev.devAddr != None:
            # delete the old mapping
            del self.addrToDevMap[dev.devAddr]
        newDevAddr = self.genDevAddr()
        self.addrToDevMap[newDevAddr] = dev
        self.logger.info("[handleJoinRequest] Allocated devAddr %x"%newDevAddr)

        appNonce = random.randint(0, (1<<24)-1) & 0xFFFFFF
        # This method will generate and queue the join-accept message
        dev.onJoin(newDevAddr, appNonce, devNonce, self.netID)

class DownlinkMessage:
    def __init__(self, payloadByteStr, rxWindow):
        self.payloadSize = len(payloadByteStr)
        self.rxWindow = rxWindow
        self.payloadBase64 = base64.b64encode(payloadByteStr)