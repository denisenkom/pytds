import socket
import struct
import errno
import select
import logging
import signal
from tds import *

logger = logging.getLogger(__name__)

USE_POLL = hasattr(select, 'poll')
USE_CORK = hasattr(socket, 'TCP_CORK')
if USE_POLL:
    TDSSELREAD = select.POLLIN
    TDSSELWRITE = select.POLLOUT
else:
    TDSSELREAD = 1
    TDSSELWRITE = 2
TDSSELERR = 0
TDSPOLLURG = 0x8000


def tds_open_socket(tds, host, port, timeout=0):
    if not port:
        port = 1433
    #tds = _Tds(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
    #tds._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, struct.pack('i', 1))
    #tds._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, struct.pack('i', 1))
    #if not timeout:
    #    timeout = 90000
    #tds._sock.setblocking(0)
    #try:
    #    tds._sock.connect((host, port))
    #except socket.error as e:
    #    if e.errno != errno.EINPROGRESS:
    #        raise e
    #if not tds_select(tds, TDSSELWRITE|TDSSELERR, timeout):
    #    tds_close_socket(tds)
    #    logger.error('tds_open_socket() failed')
    #    raise Exception('TDSECONN')
    #print socket.getsockopt(tds._sock, SOL_SOCKET, SO_ERROR)
    if not timeout:
        timeout = 90000
    tds._sock = socket.create_connection((host, port), timeout)
    return tds

def tds_close_socket(tds):
    if not tds.is_dead():
        tds._sock.close()
        tds_set_state(tds, TDS_DEAD)

def tds_select(tds, tds_sel, timeout_seconds):
    poll_seconds = 1 if tds.int_handler else timeout_seconds
    seconds = timeout_seconds
    while timeout_seconds is None or seconds > 0:
        timeout = poll_seconds * 1000 if poll_seconds else None
        if USE_POLL:
            poll = select.poll()
            poll.register(tds._sock, tds_sel)
            poll.register(tds_conn(tds).s_signaled, select.POLLIN)
            res = poll.poll(timeout)
            result = 0
            if res:
                for fd, events in res:
                    if events & select.POLLERR:
                        raise Exception('Error event occured')
                    if fd == tds._sock.fileno():
                        result = events
                    else:
                        result |= TDSPOLLURG
                return result
            if tds.int_handler:
                tds.int_handler()
        else:
            read = []
            write = []
            if tds_sel == TDSSELREAD:
                read = [tds._sock]
            if tds_sel == TDSSELWRITE:
                write = [tds._sock]
            r, w, x = select.select(read, write, [], timeout)
            if x:
                return TDSSELERR
            if r or w:
                return 1
        seconds -= poll_seconds
    return 0

def tds_put_cancel(tds):
    tds._writer.begin_packet(TDS_CANCEL)
    tds._writer.flush()
    tds.in_cancel = 1

def tds_ssl_deinit(tds):
    if tds_conn(tds).tls_session:
        gnutls_deinit(tds_conn(tds).tls_session)
        #tds_conn(tds).tls_session = None
    if tds_conn(tds).tls_credentials:
        gnutls_certificate_free_credentials(tds_conn(tds).tls_credentials)
        #tds_conn(tds).tls_credentials = None

#
# Get port of all instances
# @return default port number or 0 if error
# @remark experimental, cf. MC-SQLR.pdf.
#
def tds7_get_instances(ip_addr):
    s = socket.socket(type=socket.SOCK_DGRAM)
    try:
        # 
        # Request the instance's port from the server.  
        # There is no easy way to detect if port is closed so we always try to
        # get a reply from server 16 times. 
        #
        for num_try in range(16):
            # send the request
            s.sendto('\x03', (ip_addr, 1434))
            msg = s.recv(16*1024-1)
            # got data, read and parse
            if len(msg) > 3 and msg[0] == '\x05':
                tokens = msg[3:].split(';')
                results = {}
                instdict = {}
                got_name = False
                for token in tokens:
                    if got_name:
                        instdict[name] = token
                        got_name = False
                    else:
                        name = token
                        if not name:
                            if not instdict:
                                break
                            results[instdict['InstanceName']] = instdict
                            instdict = {}
                            continue
                        got_name = True
                return results

    finally:
        s.close()
