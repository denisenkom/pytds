from StringIO import StringIO
from tds import *
from net import *
from iconv import tds_iconv_alloc
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


class _TdsSocket(object):
    def __init__(self):
        self.conn = _TdsConn()
        self.out_pos = 8
        self.login = None
        self.int_handler = None
        #self.in_pos = 0
        #self.in_len = 0
        self.msg_handler = None
        self.res_info = None
        self.in_cancel = False
        #self.env = {'block_size': len(self.out_buf)}
        self.env = _TdsEnv()
        self.wire_mtx = None
        self.current_results = None
        self.param_info = None
        self.cur_cursor = None
        self.use_iconv = True
        self.collation = None
        self.tds72_transaction = '\x00\x00\x00\x00\x00\x00\x00\x00'
        self.has_status = False
        self.messages = []
        self._reader = _TdsReader(self)

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

def tds_alloc_socket(context, bufsize):
    tds_socket = _TdsSocket()
    tds_set_ctx(tds_socket, context)
    tds_socket.in_buf_max = 0
    tds_conn(tds_socket).s_signal = tds_conn(tds_socket).s_signaled = None
    tds_socket.out_buf = bytearray(bufsize + TDS_ADDITIONAL_SPACE)

    tds_set_parent(tds_socket, None)
    tds_socket.env.block_size = bufsize

    tds_conn(tds_socket).use_iconv = True
    tds_iconv_alloc(tds_socket)

    # Jeff's hack, init to no timeout
    tds_socket.query_timeout = 0
    from write import tds_init_write_buf
    tds_init_write_buf(tds_socket)
    tds_set_s(tds_socket, None)
    import socket
    if hasattr(socket, 'socketpair'):
        tds_conn(tds_socket).s_signal, tds_conn(tds_socket).s_signaled = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    tds_socket.state = TDS_DEAD
    from threadsafe import TDS_MUTEX_INIT
    tds_socket.write_mtx = TDS_MUTEX_INIT(tds_socket.wire_mtx)
    return tds_socket

def tds_realloc_socket(tds, bufsize):
    #unsigned char *new_out_buf;

    assert tds and tds.out_buf

    if tds.env.block_size == bufsize:
        return tds

    if tds.out_pos <= bufsize and bufsize > 0:
        if bufsize > tds.env.block_size:
            tds.out_buf.extend('\0'*(bufsize - len(tds.out_buf)))
        else:
            tds.out_buf = tds.out_buf[0:bufsize]
        tds.env.block_size = bufsize
        return tds
    return None

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
        #free(tds->out_buf)
        from net import tds_ssl_deinit, tds_close_socket
        tds_ssl_deinit(tds)
        tds_close_socket(tds);
        if tds_conn(tds).s_signal is not None:
            tds_conn(tds).s_signal.close()
        if tds_conn(tds).s_signaled is not None:
            tds_conn(tds).s_signaled.close()
        #tds_iconv_free(tds);
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
        self.char_conv = None
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

def tds_alloc_login(use_environment):
    server_name = TDS_DEF_SERVER

    login = _TdsLogin()
    login.server_name = ''
    login.language = ''
    login.server_charset = ''
    login.client_host_name = ''
    login.server_host_name = ''
    login.app_name = ''
    login.user_name = ''
    login.password = ''
    login.library = ''
    login.ip_addr = ''
    login.database = ''
    login.dump_file = ''
    login.client_charset = ''
    login.instance_name = ''
    login.server_realm_name = ''

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
