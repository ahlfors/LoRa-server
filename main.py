import connection
import logging
import threading
import time
import loraMac

HOST = ''
PORT_UPSTREAM = 1680
PORT_DOWNSTREAM = 1681

NETWORK_ID = 0x0A
TEST_DEVICE_EUI = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
TEST_APPLICATION_EUI = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
TEST_APPLICATION_KEY = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]

def main():
    logging.getLogger().setLevel(logging.INFO)

    # Create the LoRaMac layer processor and the up/down stream workers
    downPool = connection.DownstreamWorkerPool()
    mac = loraMac.LoRaMac(NETWORK_ID, downPool.sendToGateway)
    downPool.setGwChangeCallback(mac.onGatewayOnline, mac.onGatewayOffline)
    upPool = connection.UpstreamWorkerPool(mac)

    # Manually register a test end device
    mac.registerEndDevice(TEST_APPLICATION_EUI, TEST_DEVICE_EUI, TEST_APPLICATION_KEY)

    # up/down stream connection acceptors
    upAcceptor = connection.ConnectionAcceptor(HOST, PORT_UPSTREAM, upPool.handleNewConnection)
    downAcceptor = connection.ConnectionAcceptor(HOST, PORT_DOWNSTREAM, downPool.handleNewConnection)
    upAcceptor.startListening()
    print "Start accepting upstream requests on %d..."%PORT_UPSTREAM
    downAcceptor.startListening()
    print "Start accepting downstream requests %d..."%PORT_DOWNSTREAM

    # Main loop. Idle..
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print "KeyboardInterrupt received... Cleaning up..."
            break

    # [TODO] Clean up
    print "Cleanup done. Bye!"

if __name__ == '__main__':
    main()