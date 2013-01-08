import struct
import logging
from StringIO import StringIO
import socket
import struct
import errno
import select
import lcid
from collate import *
from tdsproto import *

logger = logging.getLogger()


TDS_IDLE = 0
TDS_QUERYING = 1
TDS_PENDING = 2
TDS_READING = 3
TDS_DEAD = 4
state_names = ['IDLE', 'QUERYING', 'PENDING', 'READING', 'DEAD']

SUPPORT_NBCROW = True

TDS_ENCRYPTION_OFF = 0
TDS_ENCRYPTION_REQUEST = 1
TDS_ENCRYPTION_REQUIRE = 2

# tds protocol versions
TDS70       = 0x70000000
TDS71       = 0x71000000
TDS71rev1   = 0x71000001
TDS72       = 0x72090002
TDS73A      = 0x730A0003
TDS73B      = 0x730B0003
TDS74       = 0x74000004

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


def IS_TDS42(x): return x.tds_version==0x402
def IS_TDS46(x): return x.tds_version==0x406
def IS_TDS50(x): return x.tds_version==0x500
def IS_TDS70(x): return x.tds_version==TDS70
def IS_TDS71(x): return x.tds_version in (TDS71, TDS71rev1)
def IS_TDS72(x): return x.tds_version==TDS72
def IS_TDS73(x): return x.tds_version in (TDS73A, TDS73B)
def IS_TDS7_PLUS(x): return x.tds_version>=TDS70
def IS_TDS71_PLUS(x): return x.tds_version>=TDS71
def IS_TDS72_PLUS(x): return x.tds_version>=TDS72
def IS_TDS73_PLUS(x): return x.tds_version>=TDS73A

TDS_NO_COUNT = -1

TDS_ROW_RESULT        = 4040
TDS_PARAM_RESULT      = 4042
TDS_STATUS_RESULT     = 4043
TDS_MSG_RESULT        = 4044
TDS_COMPUTE_RESULT    = 4045
TDS_CMD_DONE          = 4046
TDS_CMD_SUCCEED       = 4047
TDS_CMD_FAIL          = 4048
TDS_ROWFMT_RESULT     = 4049
TDS_COMPUTEFMT_RESULT = 4050
TDS_DESCRIBE_RESULT   = 4051
TDS_DONE_RESULT       = 4052
TDS_DONEPROC_RESULT   = 4053
TDS_DONEINPROC_RESULT = 4054
TDS_OTHERS_RESULT     = 4055

TDS_TOKEN_RES_OTHERS    = 0
TDS_TOKEN_RES_ROWFMT    = 1
TDS_TOKEN_RES_COMPUTEFMT= 2
TDS_TOKEN_RES_PARAMFMT  = 3
TDS_TOKEN_RES_DONE      = 4
TDS_TOKEN_RES_ROW       = 5
TDS_TOKEN_RES_COMPUTE   = 6
TDS_TOKEN_RES_PROC      = 7
TDS_TOKEN_RES_MSG       = 8

TDS_HANDLE_ALL = 0

def _gen_return_flags():
    _globs = globals()
    prefix = 'TDS_TOKEN_RES_'
    for key, value in globals().items():
        if key.startswith(prefix):
            _globs['TDS_RETURN_' + key[len(prefix):]] = 1 << (value * 2)
            _globs['TDS_STOPAT_' + key[len(prefix):]] = 2 << (value * 2)
_gen_return_flags()


TDS_TOKEN_RESULTS = TDS_RETURN_ROWFMT|TDS_RETURN_COMPUTEFMT|TDS_RETURN_DONE|\
        TDS_STOPAT_ROW|TDS_STOPAT_COMPUTE|TDS_RETURN_PROC
TDS_TOKEN_TRAILING = TDS_STOPAT_ROWFMT|TDS_STOPAT_COMPUTEFMT|TDS_STOPAT_ROW|\
        TDS_STOPAT_COMPUTE|TDS_STOPAT_MSG|TDS_STOPAT_OTHERS

TDS_DONE_FINAL          = 0x00  # final result set, command completed successfully. */
TDS_DONE_MORE_RESULTS   = 0x01  # more results follow */
TDS_DONE_ERROR          = 0x02  # error occurred */
TDS_DONE_INXACT         = 0x04  # transaction in progress */
TDS_DONE_PROC           = 0x08  # results are from a stored procedure */
TDS_DONE_COUNT          = 0x10  # count field in packet is valid */
TDS_DONE_CANCELLED      = 0x20  # acknowledging an attention command (usually a cancel) */
TDS_DONE_EVENT          = 0x40  # part of an event notification. */
TDS_DONE_SRVERROR       = 0x100 # SQL server server error */

# after the above flags, a TDS_DONE packet has a field describing the state of the transaction */
TDS_DONE_NO_TRAN        = 0     # No transaction in effect */
TDS_DONE_TRAN_SUCCEED   = 1     # Transaction completed successfully */
TDS_DONE_TRAN_PROGRESS  = 2     # Transaction in progress */
TDS_DONE_STMT_ABORT     = 3     # A statement aborted */
TDS_DONE_TRAN_ABORT     = 4     # Transaction aborted */

TDS_NO_MORE_RESULTS = 1
TDS_SUCCESS         = 0
TDS_FAIL            = -1
TDS_CANCELLED       = -2
def TDS_FAILED(rc): return rc<0
def TDS_SUCCEED(rc): return rc>=0

def is_blob_type(x): return x in (SYBTEXT, SYBIMAGE, SYBNTEXT)
def is_blob_col(col): return (col.column_varint_size > 2)
# large type means it has a two byte size field
# define is_large_type(x) (x>128)
def is_numeric_type(x): return x in (SYBNUMERIC, SYBDECIMAL)
def is_unicode_type(x): return x in (XSYBNVARCHAR,XSYBNCHAR,SYBNTEXT,SYBMSXML)
def is_collate_type(x): return x in (XSYBVARCHAR, XSYBCHAR, SYBTEXT, XSYBNVARCHAR, XSYBNCHAR, SYBNTEXT)
def is_ascii_type(x): return x in (XSYBCHAR,XSYBVARCHAR,SYBTEXT,SYBCHAR,SYBVARCHAR)
def is_char_type(x): return is_unicode_type(x) or is_ascii_type(x)
def is_similar_type(x, y): return is_char_type(x) and is_char_type(y) or is_unicode_type(x) and is_unicode_type(y)

def tds_conn(tds): return tds

def TDS_IS_SOCKET_INVALID(sock):
    return sock is None

def IS_TDSDEAD(tds):
    return tds is None or tds._sock is None

TDS_DEF_BLKSZ		= 512
TDS_DEF_CHARSET		= "iso_1"
TDS_DEF_LANG		= "us_english"

def tds_set_s(tds, sock):
    tds._sock = sock

def tds_get_s(tds):
    return tds._sock

TDS_ADDITIONAL_SPACE = 0

to_server = 0
to_client = 1

TDS_DATETIME = struct.Struct('<ll')
TDS_DATETIME4 = struct.Struct('<HH')


#
# Quote an id
# \param tds    state information for the socket and the TDS protocol
# \param buffer buffer to store quoted id. If NULL do not write anything 
#        (useful to compute quote length)
# \param id     id to quote
# \param idlen  id length
# \result written chars (not including needed terminator)
#
def tds_quote_id(tds, id):
    # quote always for mssql
    if TDS_IS_MSSQL(tds) or tds_conn(tds).product_version >= TDS_SYB_VER(12, 5, 1):
        return '[{0}]'.format(id.replace(']', ']]'))

    return '"{0}"'.format(id.replace('"', '""'))

# Check if product is Sybase (such as Adaptive Server Enterrprice). x should be a TDSSOCKET*.
def TDS_IS_SYBASE(x): return not tds_conn(x).product_version & 0x80000000
# Check if product is Microsft SQL Server. x should be a TDSSOCKET*.
def TDS_IS_MSSQL(x): return tds_conn(x).product_version & 0x80000000

# store a tuple of programming error codes
prog_errors = (
    102,    # syntax error
    207,    # invalid column name
    208,    # invalid object name
    2812,   # unknown procedure
    4104    # multi-part identifier could not be bound
)

# store a tuple of integrity error codes
integrity_errors = (
    515,    # NULL insert
    547,    # FK related
    2601,   # violate unique index
    2627,   # violate UNIQUE KEY constraint
)

# exception hierarchy
class Warning(StandardError):
    pass

class Error(StandardError):
    pass

class InterfaceError(Error):
    pass

class DatabaseError(Error):
    @property
    def message(self):
        if self.procname:
            return 'SQL Server message %d, severity %d, state %d, ' \
                'procedure %s, line %d:\n%s' % (self.number,
                self.severity, self.state, self.procname,
                self.line, self.text)
        else:
            return 'SQL Server message %d, severity %d, state %d, ' \
                'line %d:\n%s' % (self.number, self.severity,
                self.state, self.line, self.text)

class DataError(Error):
    pass

class OperationalError(DatabaseError):
    pass

class LoginError(OperationalError):
    pass

class IntegrityError(DatabaseError):
    pass

class InternalError(DatabaseError):
    pass

class ProgrammingError(DatabaseError):
    pass

class NotSupportedError(DatabaseError):
    pass

#############################
## DB-API type definitions ##
#############################
STRING = 1
BINARY = 2
NUMBER = 3
DATETIME = 4
DECIMAL = 5
ROWID = 6

# stored procedure output parameter
class output:
    #property
    def type(self):
        """
        This is the type of the parameter.
        """
        return self._type

    @property
    def value(self):
        """
        This is the value of the parameter.
        """
        return self._value


    def __init__(self, param_type, value=None):
        self._type = param_type
        self._value = value

class Binary(str):
    def __repr__(self):
        return 'Binary({0})'.format(super(Binary, self).__repr__())

class _Default:
    pass

default = _Default()

def raise_db_exception(tds):
    msg = tds.messages[-1]
    msg_no = msg['msgno']
    error_msg = msg['message']
    if msg_no in prog_errors:
        ex = ProgrammingError(error_msg)
    elif msg_no in integrity_errors:
        ex = IntegrityError(error_msg)
    else:
        ex = OperationalError(error_msg)
    ex.msg_no = msg['msgno']
    ex.text = msg['message']
    ex.srvname = msg['server']
    ex.procname = msg['proc_name']
    ex.number = msg['msgno']
    ex.severity = msg['severity']
    ex.state = msg['state']
    ex.line = msg['line_number']
    #self.cancel()
    tds.messages = []
    raise ex

class InternalProc(object):
    def __init__(self, proc_id, name):
        self.proc_id = proc_id
        self.name = name
    def __unicode__(self):
        return self.name

SP_EXECUTESQL = InternalProc(TDS_SP_EXECUTESQL, 'sp_executesql')

def tds_mutex_trylock(mutex):
    pass

def tds_mutex_unlock(mutex):
    pass

TDS_MUTEX_TRYLOCK = tds_mutex_trylock
def TDS_MUTEX_LOCK(mutex):
    pass
TDS_MUTEX_UNLOCK = tds_mutex_unlock
def TDS_MUTEX_INIT(something):
    return None

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
        self._transport = tds
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
        return self._tds.emul_little_endian

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
        chunks = [res]
        left = size - len(res)
        while left:
            buf = self.read(left)
            chunks.append(buf)
            left -= len(buf)
        return ''.join(chunks)

    def read(self, size):
        if self._pos >= len(self._buf):
            if self._have >= self._size:
                self._read_packet()
            else:
                self._buf = self._transport.recv(self._size - self._have)
                self._pos = 0
                self._have += len(self._buf)
        res = self._buf[self._pos:self._pos+size]
        self._pos += len(res)
        return res

    def _read_packet(self):
        header = self._transport.recv(_header.size)
        if len(header) < _header.size:
            self._pos = 0
            if self._tds.state != TDS_IDLE and len(header) == 0:
                self._transport.close()
            raise Exception('Reading header error')
        logger.debug('Received header')
        self._type, self._status, self._size, self._spid = _header.unpack(header)
        self._have = _header.size
        assert self._size > self._have, 'Empty packet doesn make any sense'
        self._buf = self._transport.recv(self._size - self._have)
        self._have += len(self._buf)
        self._pos = 0

    def read_whole_packet(self):
        self._read_packet()
        return self.readall(self._size - _header.size)

class _TdsWriter(object):
    def __init__(self, tds, bufsize):
        self._tds = tds
        self._transport = tds
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
        self._transport.send(self._buf[:self._pos], final)
        self._pos = 8

class MemoryChunkedHandler(object):
    def begin(self, column, size):
        logger.debug('MemoryChunkedHandler.begin(sz=%d)', size)
        self.size = size
        self._chunks = []
    def new_chunk(self, val):
        #logger.debug('MemoryChunkedHandler.new_chunk(sz=%d)', len(val))
        self._chunks.append(val)
    def end(self):
        return ''.join(self._chunks)

class _TdsSession(object):
    def __init__(self, tds, transport):
        self.out_pos = 8
        self.res_info = None
        self.in_cancel = False
        self.wire_mtx = None
        self.current_results = None
        self.param_info = None
        self.cur_cursor = None
        self.has_status = False
        self._transport = transport
        self._reader = _TdsReader(tds)
        self._reader._transport = transport
        self._writer = _TdsWriter(tds, tds._bufsize)
        self._writer._transport = transport
        self.in_buf_max = 0
        self.state = TDS_IDLE
        self.write_mtx = TDS_MUTEX_INIT(self.wire_mtx)
        self._tds = tds
        self.messages = []
        self.chunk_handler = tds.chunk_handler
        self.rows_affected = -1

    def is_dead(self):
        return self.state == TDS_DEAD

    @property
    def tds_version(self):
        return self._tds.tds_version

    @property
    def conn(self):
        return self._tds

    def close(self):
        self._transport.close()

    def set_state(self, state):
        assert 0 <= state < len(state_names)
        assert 0 <= self.state < len(state_names)
        prior_state = self.state
        if state == prior_state:
            return state
        if state == TDS_PENDING:
            if prior_state in (TDS_READING, TDS_QUERYING):
                self.state = TDS_PENDING
                tds_mutex_unlock(self.wire_mtx)
            else:
                logger.error('logic error: cannot chage query state from {0} to {1}'.\
                        format(state_names[prior_state], state_names[state]))
        elif state == TDS_READING:
            # transition to READING are valid only from PENDING
            if tds_mutex_trylock(self.wire_mtx):
                return self.state
            if self.state != TDS_PENDING:
                tds_mutex_unlock(self.wire_mtx)
                logger.error('logic error: cannot change query state from {0} to {1}'.\
                        format(state_names[prior_state], state_names[state]))
            else:
                self.state = state
        elif state == TDS_IDLE:
            if prior_state == TDS_DEAD and tds_get_s(self) is None:
                logger.error('logic error: cannot change query state from {0} to {1}'.\
                        format(state_names[prior_state], state_names[state]))
            elif prior_state in (TDS_READING, TDS_QUERYING):
                tds_mutex_unlock(self.wire_mtx)
            self.state = state
        elif state == TDS_DEAD:
            if prior_state in (TDS_READING, TDS_QUERYING):
                tds_mutex_unlock(self.wire_mtx)
            self.state = state
        elif state == TDS_QUERYING:
            if tds_mutex_trylock(self.wire_mtx):
                return self.state
            if self.state == TDS_DEAD:
                tds_mutex_unlock(self.wire_mtx)
                logger.error('logic error: cannot change query state from {0} to {1}'.\
                        format(state_names[prior_state], state_names[state]))
            elif self.state != TDS_IDLE:
                tds_mutex_unlock(self.wire_mtx)
                logger.error('logic error: cannot change query state from {0} to {1}'.\
                        format(state_names[prior_state], state_names[state]))
            else:
                self.rows_affected = TDS_NO_COUNT
                self.internal_sp_called = 0
                self.state = state
        else:
            assert False
        return self.state

class _TdsSocket(object):
    def __init__(self, login):
        self._is_connected = False
        self._bufsize = login.blocksize
        self.login = None
        self.int_handler = None
        self.msg_handler = None
        self.env = _TdsEnv()
        self.collation = None
        self.tds72_transaction = None
        self.authentication = None
        self._mars_enabled = False
        tds_conn(self).s_signal = tds_conn(self).s_signaled = None
        self.emul_little_endian = True
        self.chunk_handler = MemoryChunkedHandler()
        self._main_session = _TdsSession(self, self)

        # Jeff's hack, init to no timeout
        self.query_timeout = login.connect_timeout if login.connect_timeout else login.query_timeout
        self._sock = None
        import socket
        if hasattr(socket, 'socketpair'):
            tds_conn(self).s_signal, tds_conn(self).s_signaled = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._login = login
        self.tds_version = tds_version = login.tds_version
        self.emul_little_endian = login.emul_little_endian
        if IS_TDS7_PLUS(self):
            # TDS 7/8 only supports little endian
            self.emul_little_endian = True
        if IS_TDS7_PLUS(self) and login.instance_name and not login.port:
            instances = tds7_get_instances(login.server_name)
            if login.instance_name not in instances:
                raise LoginError("Instance {0} not found on server {1}".format(login.instance_name, login.server_name))
            instdict = instances[login.instance_name]
            if 'tcp' not in instdict:
                raise LoginError("Instance {0} doen't have tcp connections enabled".format(login.instance_name))
            login.port = int(instdict['tcp'])
        connect_timeout = login.connect_timeout

        if not login.port:
            login.port = 1433
        try:
            tds_open_socket(self, login.server_name, login.port, connect_timeout)
        except socket.error as e:
            raise LoginError("Cannot connect to server '{0}': {1}".format(login.server_name, e), e)
        try:
            from login import tds_login
            tds_login(self._main_session, login)
            text_size = login.text_size
            if self.mars_enabled:
                self._setup_smp()
            self._is_connected = True
            q = []
            if text_size:
                q.append('set textsize {0}'.format(int(text_size)))
            if login.database and self.env.database != login.database:
                q.append('use ' + tds_quote_id(self, login.database))
            if q:
                tds_submit_query(tds._main_session, ''.join(q))
                tds_process_simple_query(tds._main_session)
        except:
            self.close()
            raise

    def _setup_smp(self):
        from smp import SmpManager
        self._smp_manager = SmpManager(self)
        self._main_session = _TdsSession(self, self._smp_manager.create_session())

    @property
    def mars_enabled(self): return self._mars_enabled

    @property
    def main_session(self):
        return self._main_session

    def create_session(self):
        return _TdsSession(self, self._smp_manager.create_session())

    def _read(self, size):
        events = tds_select(self, TDSSELREAD, self.query_timeout)
        if events & TDSPOLLURG:
            buf = tds_conn(self).s_signaled.read(size)
            if not self.in_cancel:
                tds_put_cancel(self)
            return buf
        elif events:
            buf = self._sock.recv(size)
            if len(buf) == 0:
                self.close()
                raise Error('Server closed connection')
            return buf
        else:
            self.close()
            raise Error('Timeout')

    def recv(self, size):
        return self._read(size)

    def send(self, data, final):
        return self._write(data, final)

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
                    self.close()
                    raise
            pos += nput
        if final and USE_CORK:
            self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 0)
            self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 1)

    def is_connected(self):
        return self._is_connected

    def close(self):
        self._is_connected = False
        if self._sock is not None:
            self._sock.close()
        self._main_session.state = TDS_DEAD
        if self.authentication:
            self.authentication.close()
            self.authentication = None
        #tds_ssl_deinit(self)
        if self.s_signal is not None:
            self.s_signal.close()
        if self.s_signaled is not None:
            self.s_signaled.close()

class _Column(object):
    def __init__(self):
        self.char_codec = None
        self.column_name = ''
        self.value = None

    def __repr__(self):
        return '<_Column(name={0}), value={1}>'.format(self.column_name, repr(self.value))

class _Results(object):
    def __init__(self):
        self.columns = []
        self.row_count = 0

def tds_open_socket(tds, host, port, timeout=0):
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
    tds._sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    return tds

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
