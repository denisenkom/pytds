import socket
import struct
import errno
import select
import logging
import signal
from tds import *
from util import *

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
                tds.int_handler(tds_get_parent(tds))
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

def tds_goodread(tds, buflen, unfinished):
    got = 0
    parts = []
    while True:
        if tds.is_dead():
            raise Exception('Tds is dead')
        try:
            events = tds_select(tds, TDSSELREAD, tds.query_timeout)
        except:
            tds_close_socket(tds)
            raise
        if events & TDSPOLLURG:
            parts.append(tds_conn(tds).s_signaled.read(buflen))
            if not tds.in_cancel:
                tds_put_cancel(tds)
            continue
        elif events:
            try:
                buf = tds._sock.recv(buflen)
            except socket.error as e:
                if e.errno == errno.EWOULDBLOCK:
                    continue
                else:
                    tds_close_socket(tds)
                    raise tdserror(tds, TDSEREAD, e.errno)
            else:
                if len(buf) == 0:
                    tds_close_socket(tds)
                    raise tdserror(tds, TDSESEOF, 0)
                else:
                    parts.append(buf)
        else:
            tds_close_socket(tds)
            raise tdserror(tds, TDSETIME, 0)
        got += len(buf)
        buflen -= len(buf)
        if buflen <= 0:
            break
        if unfinished and got:
            break
    return ''.join(parts)


def goodread(tds, buflen):
    return tds_goodread(tds, buflen, False)

def tds_read_packet(tds):
    if tds.is_dead():
        raise Exception('Read attempt when state is TDS_DEAD')
    header = goodread(tds, 8)
    if len(header) < 8:
        tds.in_len = 0
        tds.in_pos = 0
        if tds.state != TDS_IDLE and len(header) == 0:
            tds_close_socket(tds)
        raise Exception('Reading header error')
    logger.debug('Received header')
    in_flag, size = struct.unpack('>BxHxxxx', header)
    have = 8
    tds.in_buf = bytearray(header)
    while have < size:
        buf = goodread(tds, size - have)
        have += len(buf)
        tds.in_buf.extend(buf)
    tds.in_flag = in_flag
    tds.in_len = have
    tds.in_pos = 8
    return tds.in_len

def tds_goodwrite(tds, buf, size, last):
    pos = 0
    while pos < size:
        res = tds_select(tds, TDSSELWRITE, tds.query_timeout)
        if not res:
            #timeout
            raise Exception('timeout')
        try:
            flags = 0
            if hasattr(socket, 'MSG_NOSIGNAL'):
                flags |= socket.MSG_NOSIGNAL
            if not last:
                if hasattr(socket, 'MSG_MORE'):
                    flags |= socket.MSG_MORE
            nput = tds._sock.send(buf[pos:size], flags)
        except socket.error as e:
            if e.errno != errno.EWOULDBLOCK:
                tds_close_socket(tds)
                raise
        pos += nput
    if last and USE_CORK:
        tds._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 0)
        tds._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 1)
    return size

def tds_write_packet(tds, final):
    tds.out_buf[0] = tds.out_flag
    tds.out_buf[1] = 1 if final else 0
    struct.pack_into('>H', tds.out_buf, 2, tds.out_pos)
    if IS_TDS7_PLUS(tds) and not tds.login:
        tds.out_buf[6] = 1
    logger.debug('Sending packet {0}'.format(repr(tds.out_buf[0:tds.out_pos])))
    sent = tds_goodwrite(tds, tds.out_buf, tds.out_pos, final)
    tds.out_pos = 8
    if sent <= 0:
        raise Exception('TDS_FAIL')

def tds_put_cancel(tds):
    out_buf = bytearray(8)
    out_buf[0] = TDS_CANCEL  # out_flag
    out_buf[1] = 1 # final
    out_buf[2] = 0
    out_buf[3] = 8
    if IS_TDS7_PLUS(tds) and not tds.login:
        out_buf[6] = 0x01

    logger.debug("Sending packet {0}".format(repr(out_buf)))

    if tds_conn(tds).tls_session:
        sent = tds_conn(tds).tls_session.send(out_buf)
    else:
        sent = tds_goodwrite(tds, out_buf, len(out_buf), 1)

    if sent > 0:
        tds.in_cancel = 1

    # GW added in check for write() returning <0 and SIGPIPE checking
    if sent <= 0:
        raise Exception('TDS_FAIL')
    return TDS_SUCCESS

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
