import connection
import logging
import threading
import time

HOST = ''
PORT_UPSTREAM = 1680
PORT_DOWNSTREAM = 1681

def dum(dum):
    print dum

def main():
    logging.getLogger().setLevel(logging.INFO)
    loraMac = None
    upPool = connection.UpstreamWorkerPool(loraMac)
    downPool = connection.DownstreamWorkerPool(dum,dum)
    upAcceptor = connection.ConnectionAcceptor(HOST, PORT_UPSTREAM, upPool.handleNewConnection)
    downAcceptor = connection.ConnectionAcceptor(HOST, PORT_DOWNSTREAM, downPool.handleNewConnection)

    upAccThread = upAcceptor.startListening()
    print "Start accepting upstream requests on %d..."%PORT_UPSTREAM
    downAccThread = downAcceptor.startListening()
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