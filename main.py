import connection
import time
import loraMac

HOST = ''
PORT_UPSTREAM = 1680
PORT_DOWNSTREAM = 1681

NETWORK_ID = 0x0A
TEST_DEVICE_EUI = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
TEST_APPLICATION_EUI = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
TEST_APPLICATION_KEY = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 
                        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]

def main():
    # Create the LoRaMac layer processor and the connection manager
    macSrv = loraMac.LoRaMacServer(NETWORK_ID)
    connMgr = connection.ConnectionManagerUDP(HOST, PORT_UPSTREAM,
                                              PORT_DOWNSTREAM, 
                                              macSrv.processRawRxPayload)
    macSrv.setGatewaySenderFn(connMgr.sendToGateway)

    # Manually register a test end device
    macSrv.registerEndDevice(TEST_APPLICATION_EUI, TEST_DEVICE_EUI, 
                             TEST_APPLICATION_KEY)

    # Main loop. Idle..
    connMgr.startServing()
    print "Serving on port %d(up) and %d(down)"%(PORT_UPSTREAM, PORT_DOWNSTREAM)
    while True:
        try:
            time.sleep(5)
            macSrv.scheduleAppDownlink(TEST_APPLICATION_EUI, TEST_DEVICE_EUI,
                                       45, "Yo I hear you!")
        except KeyboardInterrupt:
            print "Cleaning up......"
            break

    connMgr.shutdown()
    print "Cleanup done. Bye!"

if __name__ == '__main__':
    main()