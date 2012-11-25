from StringIO import StringIO
import lcid
from tds import *
from net import *
import logging

logger = logging.getLogger(__name__)

class _TdsConn:
    def __init__(self):
        self.tls_session = None
        self.tls_credentials = None

class _TdsEnv:
    pass

_header = struct.Struct('>BBHHxx')
_byte = struct.Struct('B')
_smallint_le = struct.Struct('<h')
_smallint_be = struct.Struct('>h')
_usmallint_le = struct.Struct('<H')
_usmallint_be = struct.Struct('>H')
_int_le = struct.Struct('<l')
_int_be = struct.Struct('>l')
_uint_le = struct.Struct('<L')
_uint_be = struct.Struct('>L')
_int8_le = struct.Struct('<q')
_int8_be = struct.Struct('>q')

class _TdsReader(object):
    def __init__(self, tds):
        self._buf = ''
        self._pos = 0 # position in the buffer
        self._have = 0 # number of bytes read from packet
        self._size = 0 # size of current packet
        self._tds = tds
        self._type = None
        self._status = None

    @property
    def packet_type(self):
        return self._type

    def unpack(self, struct):
        return struct.unpack(self.readall(struct.size))

    def get_byte(self):
        return self.unpack(_byte)[0]

    def _le(self):
        return tds_conn(self._tds).emul_little_endian

    def get_smallint(self):
        if self._le():
            return self.unpack(_smallint_le)[0]
        else:
            return self.unpack(_smallint_be)[0]

    def get_usmallint(self):
        if self._le():
            return self.unpack(_usmallint_le)[0]
        else:
            return self.unpack(_usmallint_be)[0]

    def get_int(self):
        if self._le():
            return self.unpack(_int_le)[0]
        else:
            return self.unpack(_int_be)[0]

    def get_uint(self):
        if self._le():
            return self.unpack(_uint_le)[0]
        else:
            return self.unpack(_uint_be)[0]

    def get_uint_be(self):
        return self.unpack(_uint_be)[0]

    def get_int8(self):
        if self._le():
            return self.unpack(_int8_le)[0]
        else:
            return self.unpack(_int8_be)[0]

    def read_ucs2(self, num_chars):
        buf = self.readall(num_chars*2)
        return ucs2_codec.decode(buf)[0]

    def get_collation(self):
        buf = self.readall(Collation.wire_size)
        return Collation.unpack(buf)

    def unget_byte(self):
        # this is a one trick pony...don't call it twice
        assert self._pos > 0
        self._pos -= 1

    def peek(self):
        res = self.get_byte()
        self.unget_byte()
        return res

    def skip(self, size):
        left = size
        while left:
            buf = self.read(left)
            left -= len(buf)

    def readall(self, size):
        res = self.read(size)
        if len(res) == size:
            return res
        result = StringIO(res)
        left = size - len(res)
        while left:
            buf = self.read(left)
            result.write(buf)
            left -= len(buf)
        return result.getvalue()

    def read(self, size):
        if self._pos >= len(self._buf):
            if self._have >= self._size:
                self._read_packet()
            else:
                self._buf = self._tds._read(self._size - self._have)
                self._pos = 0
                self._have += len(self._buf)
        res = self._buf[self._pos:self._pos+size]
        self._pos += len(res)
        return res

    def _read_packet(self):
        if self._tds.is_dead():
            raise Exception('Read attempt when state is TDS_DEAD')
        header = self._tds._read(_header.size)
        if len(header) < _header.size:
            tds._pos = 0
            if self._tds.state != TDS_IDLE and len(header) == 0:
                tds_close_socket(self._tds)
            raise Exception('Reading header error')
        logger.debug('Received header')
        self._type, self._status, self._size, self._spid = _header.unpack(header)
        self._have = _header.size
        assert self._size > self._have, 'Empty packet doesn make any sense'
        self._buf = self._tds._read(self._size - self._have)
        self._have += len(self._buf)
        self._pos = 0

    def read_whole_packet(self):
        self._read_packet()
        return self.readall(self._size - _header.size)

class _TdsWriter(object):
    def __init__(self, tds, bufsize):
        self._tds = tds
        self._pos = 0
        self._buf = bytearray(bufsize)

    @property
    def bufsize(self):
        return len(self._buf)

    @bufsize.setter
    def bufsize(self, bufsize):
        if len(self._buf) == bufsize:
            return

        if bufsize > len(self._buf):
            self._buf.extend('\0'*(bufsize - len(self._buf)))
        else:
            self._buf = self._buf[0:bufsize]

    def begin_packet(self, packet_type):
        self._type = packet_type
        self._pos = 8

    def pack(self, struct, *args):
        self.write(struct.pack(*args))

    def put_byte(self, value):
        self.pack(_byte, value)

    def _le(self):
        return tds_conn(self._tds).emul_little_endian

    def put_smallint(self, value):
        if self._le():
            self.pack(_smallint_le, value)
        else:
            self.pack(_smallint_be, value)

    def put_usmallint(self, value):
        if self._le():
            self.pack(_usmallint_le, value)
        else:
            self.pack(_usmallint_be, value)

    def put_smallint_be(self, value):
        self.pack(_smallint_be, value)

    def put_usmallint_be(self, value):
        self.pack(_usmallint_be, value)

    def put_int(self, value):
        if self._le():
            self.pack(_int_le, value)
        else:
            self.pack(_int_be, value)

    def put_uint(self, value):
        if self._le:
            self.pack(_uint_le, value)
        else:
            self.pack(_uint_be, value)

    def put_int_be(self, value):
        self.pack(_int_be, value)

    def put_uint_be(self, value):
        self.pack(_uint_be, value)

    def put_int8(self, value):
        if self._le():
            self.pack(_int8_le, value)
        else:
            self.pack(_int8_be, value)

    def put_collation(self, collation):
        self.write(collation.pack())

    def write(self, data):
        data_off = 0
        while data_off < len(data):
            left = len(self._buf) - self._pos
            if left <= 0:
                self._write_packet(final=False)
            else:
                to_write = min(left, len(data) - data_off)
                self._buf[self._pos:self._pos+to_write] = data[data_off:data_off+to_write]
                self._pos += to_write
                data_off += to_write

    def write_ucs2(self, s):
        self.write_string(s, ucs2_codec)

    def write_string(self, s, codec):
        for i in xrange(0, len(s), self.bufsize):
            chunk = s[i:i+self.bufsize]
            buf, consumed = codec.encode(chunk)
            assert consumed == len(chunk)
            self.write(buf)

    def flush(self):
        return self._write_packet(final=True)

    def _write_packet(self, final):
        status = 1 if final else 0
        _header.pack_into(self._buf, 0, self._type, status, self._pos, 0)
        if IS_TDS7_PLUS(self._tds) and not self._tds.login:
            self._buf[6] = 0x01
        self._tds._write(self._buf[:self._pos], final)
        self._pos = 8

class _TdsSocket(object):
    def __init__(self, context, bufsize):
        self.conn = _TdsConn()
        self.out_pos = 8
        self.login = None
        self.int_handler = None
        self.msg_handler = None
        self.res_info = None
        self.in_cancel = False
        self.env = _TdsEnv()
        self.wire_mtx = None
        self.current_results = None
        self.param_info = None
        self.cur_cursor = None
        self.collation = None
        self.tds72_transaction = '\x00\x00\x00\x00\x00\x00\x00\x00'
        self.has_status = False
        self.messages = []
        self._reader = _TdsReader(self)
        self._writer = _TdsWriter(self, bufsize)
        tds_set_ctx(self, context)
        self.in_buf_max = 0
        tds_conn(self).s_signal = tds_conn(self).s_signaled = None

        # Jeff's hack, init to no timeout
        self.query_timeout = 0
        tds_set_s(self, None)
        import socket
        if hasattr(socket, 'socketpair'):
            tds_conn(self).s_signal, tds_conn(self).s_signaled = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.state = TDS_DEAD
        from threadsafe import TDS_MUTEX_INIT
        self.write_mtx = TDS_MUTEX_INIT(self.wire_mtx)

    def is_dead(self):
        return self.state == TDS_DEAD

    def _read(self, size):
        if self.is_dead():
            raise Exception('Tds is dead')
        events = tds_select(self, TDSSELREAD, self.query_timeout)
        if events & TDSPOLLURG:
            buf = tds_conn(self).s_signaled.read(size)
            if not self.in_cancel:
                tds_put_cancel(self)
            return buf
        elif events:
            buf = self._sock.recv(size)
            if len(buf) == 0:
                tds_close_socket(self)
                raise Error('Server closed connection')
            return buf
        else:
            tds_close_socket(self)
            raise Error('Timeout')

    def _write(self, data, final):
        pos = 0
        while pos < len(data):
            res = tds_select(self, TDSSELWRITE, self.query_timeout)
            if not res:
                #timeout
                raise Error('Timeout')
            try:
                flags = 0
                if hasattr(socket, 'MSG_NOSIGNAL'):
                    flags |= socket.MSG_NOSIGNAL
                if not final:
                    if hasattr(socket, 'MSG_MORE'):
                        flags |= socket.MSG_MORE
                nput = self._sock.send(data[pos:], flags)
            except socket.error as e:
                if e.errno != errno.EWOULDBLOCK:
                    tds_close_socket(self)
                    raise
            pos += nput
        if final and USE_CORK:
            self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 0)
            self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 1)


def tds_alloc_socket(context, bufsize):
    return _TdsSocket(context, bufsize)

def tds_free_socket(tds):
    if tds:
        #if tds_conn(tds).authentication:
        #    tds_conn(tds).authentication.free(tds, tds_conn(tds).authentication)
        #tds_conn(tds).authentication = None
        #tds_free_all_results(tds)
        #tds_free_env(tds)
        #while (tds->dyns)
        #    tds_free_dynamic(tds, tds->dyns);
        #while (tds->cursors)
        #    tds_cursor_deallocated(tds, tds->cursors);
        #free(tds->in_buf)
        from net import tds_ssl_deinit, tds_close_socket
        tds_ssl_deinit(tds)
        tds_close_socket(tds);
        if tds_conn(tds).s_signal is not None:
            tds_conn(tds).s_signal.close()
        if tds_conn(tds).s_signaled is not None:
            tds_conn(tds).s_signaled.close()
        #free(tds_conn(tds)->product_name);
        #free(tds);

def tds_free_all_results(tds):
    logger.debug("tds_free_all_results()")
    if tds.current_results is tds.res_info:
        tds.current_results = None
    tds_free_results(tds.res_info)
    tds.res_info = None
    if tds.current_results is tds.param_info:
        tds.current_results = None
    tds_free_param_results(tds.param_info)
    tds.param_info = None
    tds_free_compute_results(tds)
    tds.has_status = 0
    tds.ret_status = 0

def tds_free_results(res_info):
    pass

def tds_free_param_results(param_results):
    pass

def tds_free_compute_results(compute_results):
    pass

class _OnServer(object):
    def __init__(self):
        self.column_type = None

class _Column(object):
    def __init__(self):
        self.on_server = _OnServer()
        self.char_codec = None
        self.column_nullbind = None
        self.column_varaddr = 0
        self.column_name = ''
        self.value = None

    def __repr__(self):
        return '<_Column(name={0}), value={1}>'.format(self.column_name, repr(self.value))

class _Results(object):
    pass

def tds_alloc_results(num_cols):
    res_info = _Results()
    res_info.ref_count = 1
    res_info.columns = []
    for col in range(num_cols):
        res_info.columns.append(tds_alloc_column())
    res_info.num_cols = num_cols
    res_info.row_size = 0
    res_info.row_count = 0
    return res_info

def tds_alloc_column():
    return _Column()

def tds_row_free(row):
    pass

#
# Allocate space for row store
# return NULL on out of memory
#
def tds_alloc_row(res_info):
    # compute row size
    res_info.row_size = len(res_info.columns)

    res_info.current_row = []
    res_info.row_free = tds_row_free

class _TdsLogin:
    def __init__(self):
        self.option_flag2 = 0
        self.tds_version = None
        self.emul_little_endian = False
        self.port = 1433
        self.block_size = 4096
        self.bulk_copy = False
        self.text_size = 0
        self.encryption_level = 0
        self.client_lcid = lcid.LANGID_ENGLISH_US

def tds_alloc_login(use_environment):
    server_name = TDS_DEF_SERVER

    login = _TdsLogin()
    login.server_name = ''
    login.language = '' # if empty use database default
    login.server_charset = ''
    login.server_host_name = ''
    login.app_name = ''
    login.user_name = ''
    login.password = ''
    login.library = 'python-tds'
    login.ip_addr = ''
    login.database = ''
    login.dump_file = ''
    login.client_charset = ''
    login.instance_name = ''
    login.server_realm_name = ''
    login.attach_db_file = ''

    if use_environment:
        import os
        s = os.environ.get('DSQUERY')
        if s:
            server_name = s

        s = os.environ.get('TDSQUERY')
        if s:
            server_name = s

    login.server_name = server_name
    #login.capabilities = defaultcaps
    return login

def tds_free_login(login):
    pass

class _TdsContext:
    pass

def tds_alloc_context(parent=None):
    from locale import tds_get_locale
    locale = tds_get_locale()
    if locale is None:
        return None

    context = _TdsContext()
    context.locale = locale
    context.parent = parent
    return context

class _TdsLocale:
    def __init__(self):
        self.date_fmt = None

def tds_alloc_locale():
    return _TdsLocale()
