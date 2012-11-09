import socket
import struct
import errno
import select
import logging

logger = logging.getLogger(__name__)

class _Tds(object):
    def __init__(self, sock):
        self._sock = sock
        self._dead = False

def tds_open_socket(ip_addr, port=1433, timeout=0):
    tds = _Tds(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
    #tds = socket.create_connection((ip_addr, port), timeout)
    tds._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, struct.pack('i', 1))
    tds._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, struct.pack('i', 1))
    if not timeout:
        timeout = 90000
    tds._sock.setblocking(0)
    try:
        tds._sock.connect((ip_addr, port))
    except socket.error as e:
        if e.errno != errno.EINPROGRESS:
            raise e
    return tds

def tds_close_socket(tds):
    if not tds.is_dead():
        tds._sock.close()
        tds._sock = None
        tds._dead = True

def tds_select(tds, tds_sel, timeout_seconds):
    poll_seconds = 1 if tds.int_handler else timeout_seconds
    seconds = timeout_seconds
    while timeout_seconds == 0 or seconds > 0:
        timeout = poll_seconds * 1000 if poll_seconds else None
        poll = select.poll()
        poll.register(tds._conn.fileno(), tds_sel)
        poll.register(tds.s_signaled, select.POLLIN)
        res = poll.poll(timeout)
        result = 0
        if res:
            for fd, events in res:
                if events & select.POLLERR:
                    raise Exception('Error event occured')
                if fd == tds._conn.fileno():
                    result = events
                else:
                    result |= TDSPOLLURG
            return result
        if tds.int_handler:
            tds.int_handler(tds_get_parent(tds))
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
            parts.append(tds.s_signaled.read(buflen))
            if not tds.in_cancel:
                tds_put_cancel(tds)
            continue
        elif events:
            try:
                buf = tds._conn.read(buflen)
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
    parts = [header]
    while have < size:
        buf = goodread(tds, size - have)
        have += len(buf)
        parts.append(buf)
    tds.in_flag = in_flag
    tds.in_len = have
    tds.in_pos = 8
    tds.in_buf = b''.join(parts)
    return tds.in_len

if __name__ == '__main__':
    #socket.create_connection(('localhost', 1433))
    tds_open_socket('localhost')
