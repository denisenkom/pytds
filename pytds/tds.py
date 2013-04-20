import struct
import logging
import socket
import errno
import select
import sys
import six
from datetime import datetime, date, time, timedelta
from decimal import Decimal, localcontext
from dateutil.tz import tzoffset, tzutc
import uuid
import six
import struct
import sys
from six.moves import map, reduce
from six.moves import xrange
from .collate import *
from .tdsproto import *

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

USE_CORK = hasattr(socket, 'TCP_CORK')
TDSSELREAD = 1
TDSSELWRITE = 2
TDSSELERR = 0
TDSPOLLURG = 0x8000

TDS_NO_COUNT = -1

TDS_ROW_RESULT = 4040
TDS_PARAM_RESULT = 4042
TDS_STATUS_RESULT = 4043
TDS_MSG_RESULT = 4044
TDS_COMPUTE_RESULT = 4045
TDS_CMD_DONE = 4046
TDS_CMD_SUCCEED = 4047
TDS_CMD_FAIL = 4048
TDS_ROWFMT_RESULT = 4049
TDS_COMPUTEFMT_RESULT = 4050
TDS_DESCRIBE_RESULT = 4051
TDS_DONE_RESULT = 4052
TDS_DONEPROC_RESULT = 4053
TDS_DONEINPROC_RESULT = 4054
TDS_OTHERS_RESULT = 4055

TDS_TOKEN_RES_OTHERS = 0
TDS_TOKEN_RES_ROWFMT = 1
TDS_TOKEN_RES_COMPUTEFMT = 2
TDS_TOKEN_RES_PARAMFMT = 3
TDS_TOKEN_RES_DONE = 4
TDS_TOKEN_RES_ROW = 5
TDS_TOKEN_RES_COMPUTE = 6
TDS_TOKEN_RES_PROC = 7
TDS_TOKEN_RES_MSG = 8

TDS_HANDLE_ALL = 0


def _gen_return_flags():
    _globs = {}
    prefix = 'TDS_TOKEN_RES_'
    for key, value in globals().items():
        if key.startswith(prefix):
            _globs['TDS_RETURN_' + key[len(prefix):]] = 1 << (value * 2)
            _globs['TDS_STOPAT_' + key[len(prefix):]] = 2 << (value * 2)
    globals().update(_globs)
_gen_return_flags()


TDS_TOKEN_RESULTS = TDS_RETURN_ROWFMT | TDS_RETURN_COMPUTEFMT | TDS_RETURN_DONE |\
    TDS_STOPAT_ROW | TDS_STOPAT_COMPUTE | TDS_RETURN_PROC
TDS_TOKEN_TRAILING = TDS_STOPAT_ROWFMT | TDS_STOPAT_COMPUTEFMT | TDS_STOPAT_ROW |\
    TDS_STOPAT_COMPUTE | TDS_STOPAT_MSG | TDS_STOPAT_OTHERS

TDS_DONE_FINAL = 0x00  # final result set, command completed successfully.
TDS_DONE_MORE_RESULTS = 0x01  # more results follow
TDS_DONE_ERROR = 0x02  # error occurred
TDS_DONE_INXACT = 0x04  # transaction in progress
TDS_DONE_PROC = 0x08  # results are from a stored procedure
TDS_DONE_COUNT = 0x10  # count field in packet is valid
TDS_DONE_CANCELLED = 0x20  # acknowledging an attention command (usually a cancel)
TDS_DONE_EVENT = 0x40  # part of an event notification.
TDS_DONE_SRVERROR = 0x100  # SQL server server error

# after the above flags, a TDS_DONE packet has a field describing the state of the transaction
TDS_DONE_NO_TRAN = 0        # No transaction in effect
TDS_DONE_TRAN_SUCCEED = 1   # Transaction completed successfully
TDS_DONE_TRAN_PROGRESS = 2  # Transaction in progress
TDS_DONE_STMT_ABORT = 3     # A statement aborted
TDS_DONE_TRAN_ABORT = 4     # Transaction aborted

TDS_NO_MORE_RESULTS = 1
TDS_SUCCESS = 0
TDS_FAIL = -1
TDS_CANCELLED = -2

TDS_FAILED = lambda rc: rc < 0
TDS_SUCCEED = lambda rc: rc >= 0

is_blob_type = lambda x: x in (SYBTEXT, SYBIMAGE, SYBNTEXT)
is_blob_col = lambda col: (col.column_varint_size > 2)
# large type means it has a two byte size field
# define is_large_type(x) (x>128)
is_numeric_type = lambda x: x in (SYBNUMERIC, SYBDECIMAL)
is_unicode_type = lambda x: x in (XSYBNVARCHAR, XSYBNCHAR, SYBNTEXT, SYBMSXML)
is_collate_type = lambda x: x in (XSYBVARCHAR, XSYBCHAR, SYBTEXT, XSYBNVARCHAR, XSYBNCHAR, SYBNTEXT)
is_ascii_type = lambda x: x in (XSYBCHAR, XSYBVARCHAR, SYBTEXT, SYBCHAR, SYBVARCHAR)
is_char_type = lambda x: is_unicode_type(x) or is_ascii_type(x)
is_similar_type = lambda x, y: is_char_type(x) and is_char_type(y) or is_unicode_type(x) and is_unicode_type(y)

tds_conn = lambda tds: tds

IS_TDSDEAD = lambda tds: tds is None or tds._sock is None

TDS_DEF_BLKSZ = 512
TDS_DEF_CHARSET = "iso_1"
TDS_DEF_LANG = "us_english"

TDS_ADDITIONAL_SPACE = 0

to_server = 0
to_client = 1

TDS_DATETIME = struct.Struct('<ll')
TDS_DATETIME4 = struct.Struct('<HH')


class SimpleLoadBalancer(object):
    def __init__(self, hosts):
        self._hosts = hosts

    def choose(self):
        for host in self._hosts:
            yield host


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
TDS_IS_SYBASE = lambda x: not tds_conn(x).product_version & 0x80000000
# Check if product is Microsft SQL Server. x should be a TDSSOCKET*.
TDS_IS_MSSQL = lambda x: tds_conn(x).product_version & 0x80000000

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


if sys.version_info[0] >= 3:
    exc_base_class = Exception
else:
    exc_base_class = StandardError


# exception hierarchy
class Warning(exc_base_class):
    pass


class Error(exc_base_class):
    pass


class TimeoutError(Error):
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
class DBAPITypeObject:
    def __init__(self, *values):
        self.values = set(values)

    def __eq__(self, other):
        return other in self.values

    def __cmp__(self, other):
        if other in self.values:
            return 0
        if other < self.values:
            return 1
        else:
            return -1

STRING = DBAPITypeObject(SYBVARCHAR, SYBCHAR, SYBTEXT,
                         XSYBNVARCHAR, XSYBNCHAR, SYBNTEXT,
                         XSYBVARCHAR, XSYBCHAR, SYBMSXML)
BINARY = DBAPITypeObject(SYBIMAGE, SYBBINARY, SYBVARBINARY, XSYBVARBINARY, XSYBBINARY)
NUMBER = DBAPITypeObject(SYBBIT, SYBINT1, SYBINT2, SYBINT4, SYBINT8, SYBINTN,
                         SYBREAL, SYBFLT8, SYBFLTN)
DATETIME = DBAPITypeObject(SYBDATETIME, SYBDATETIME4, SYBDATETIMN)
DECIMAL = DBAPITypeObject(SYBMONEY, SYBMONEY4, SYBMONEYN, SYBNUMERIC,
                          SYBDECIMAL)
ROWID = DBAPITypeObject()


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


class Binary(bytes):
    def __repr__(self):
        return 'Binary({0})'.format(super(Binary, self).__repr__())


class _Default:
    pass

default = _Default()


def raise_db_exception(tds):
    while True:
        msg = tds.messages[-1]
        if msg['msgno'] == 3621:  # the statement has been terminated
            tds.messages = tds.messages[:-1]
        else:
            break

    msg_no = msg['msgno']
    error_msg = ' '.join(msg['message'] for msg in tds.messages)
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
TDS_MUTEX_UNLOCK = tds_mutex_unlock


def TDS_MUTEX_LOCK(mutex):
    pass


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
_tinyint = struct.Struct('b')
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
_uint8_le = struct.Struct('<Q')
_uint8_be = struct.Struct('>Q')


def skipall(stm, size):
    res = stm.read(size)
    if len(res) == size:
        return
    elif len(res) == 0:
        raise Error('Server closed connection')
    left = size - len(res)
    while left:
        buf = stm.read(left)
        if len(buf) == 0:
            raise Error('Server closed connection')
        left -= len(buf)


def readall(stm, size):
    res = stm.read(size)
    if len(res) == size:
        return res
    elif len(res) == 0:
        raise Error('Server closed connection')
    chunks = [res]
    left = size - len(res)
    while left:
        buf = stm.read(left)
        if len(buf) == 0:
            raise Error('Server closed connection')
        chunks.append(buf)
        left -= len(buf)
    return b''.join(chunks)


def readall_fast(stm, size):
    buf, offset = stm.read_fast(size)
    if len(buf) - offset < size:
        # slow case
        buf = buf[offset:]
        buf += stm.read(size - len(buf))
        return buf, 0
    return buf, offset


class _TdsReader(object):
    def __init__(self, session, emul_little_endian):
        self._buf = ''
        self._pos = 0  # position in the buffer
        self._have = 0  # number of bytes read from packet
        self._size = 0  # size of current packet
        self._session = session
        self._transport = session._transport
        self._type = None
        self._status = None
        self._emul_little_endian = emul_little_endian

    @property
    def packet_type(self):
        return self._type

    def read_fast(self, size):
        if self._pos >= len(self._buf):
            if self._have >= self._size:
                self._read_packet()
            else:
                self._buf = self._transport.read(self._size - self._have)
                self._pos = 0
                self._have += len(self._buf)
        offset = self._pos
        self._pos += size
        return self._buf, offset

    def unpack(self, struct):
        buf, offset = readall_fast(self, struct.size)
        return struct.unpack_from(buf, offset)

    def get_byte(self):
        return self.unpack(_byte)[0]

    def _le(self):
        return self._emul_little_endian

    def get_tinyint(self):
        return self.unpack(_tinyint)[0]

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

    def get_uint8(self):
        if self._le():
            return self.unpack(_uint8_le)[0]
        else:
            return self.unpack(_uint8_be)[0]

    def get_int8(self):
        if self._le():
            return self.unpack(_int8_le)[0]
        else:
            return self.unpack(_int8_be)[0]

    def read_ucs2(self, num_chars):
        buf = readall(self, num_chars * 2)
        return ucs2_codec.decode(buf)[0]

    def read_str(self, size, codec):
        return codec.decode(readall(self, size))[0]

    def get_collation(self):
        buf = readall(self, Collation.wire_size)
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

    def read(self, size):
        buf, offset = self.read_fast(size)
        return buf[offset:offset + size]

    def _read_packet(self):
        try:
            header = readall(self._transport, _header.size)
        except TimeoutError:
            self._session._put_cancel()
            raise
        self._pos = 0
        self._type, self._status, self._size, self._session._spid = _header.unpack(header)
        self._have = _header.size
        assert self._size > self._have, 'Empty packet doesn make any sense'
        self._buf = self._transport.read(self._size - self._have)
        self._have += len(self._buf)

    def read_whole_packet(self):
        self._read_packet()
        return readall(self, self._size - _header.size)


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
            self._buf.extend(b'\0' * (bufsize - len(self._buf)))
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
                self._buf[self._pos:self._pos + to_write] = data[data_off:data_off + to_write]
                self._pos += to_write
                data_off += to_write

    def write_ucs2(self, s):
        self.write_string(s, ucs2_codec)

    def write_string(self, s, codec):
        for i in xrange(0, len(s), self.bufsize):
            chunk = s[i:i + self.bufsize]
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
        self.size = size
        self._chunks = []

    def new_chunk(self, val):
        #logger.debug('MemoryChunkedHandler.new_chunk(sz=%d)', len(val))
        self._chunks.append(val)

    def end(self):
        return b''.join(self._chunks)


class MemoryStrChunkedHandler(object):
    def begin(self, column, size):
        self.size = size
        self._chunks = []

    def new_chunk(self, val):
        #logger.debug('MemoryChunkedHandler.new_chunk(sz=%d)', len(val))
        self._chunks.append(val)

    def end(self):
        return ''.join(self._chunks)


class Bit(object):
    type = SYBBITN

    def get_declaration(self):
        return 'BIT'

    def write_info(self, w):
        w.put_byte(1)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            w.put_byte(1)
            w.put_byte(1 if value else 0)


class Int(object):
    type = SYBINTN

    def get_declaration(self):
        return 'INT'

    def write_info(self, w):
        w.put_byte(4)

    def write(self, w, val):
        if val is None:
            w.put_byte(-1)
        else:
            w.put_byte(4)
            w.put_int(val)


class BigInt(object):
    type = SYBINTN

    def get_declaration(self):
        return 'BIGINT'

    def write_info(self, w):
        w.put_byte(8)

    def write(self, w, val):
        if val is None:
            w.put_byte(-1)
        else:
            w.put_byte(8)
            w.put_int8(val)


class FloatN(object):
    type = SYBFLTN

    def get_declaration(self):
        return 'FLOAT'

    def write_info(self, w):
        w.put_byte(8)

    def write(self, w, val):
        if val is None:
            w.put_byte(-1)
        else:
            w.put_byte(8)
            w.pack(_SYBFLT8_STRUCT, val)

    def read(self, r):
        size = r.get_byte()
        if not size:
            return None
        else:
            if size != 8:
                raise InterfaceError('Invalid SYBFLTN size', size)
            return r.unpack(_SYBFLT8_STRUCT)[0]


class NVarCharMax(object):
    type = XSYBNVARCHAR

    def __init__(self, collation):
        self._collation = collation

    def get_declaration(self):
        return 'NVARCHAR(MAX)'

    def write_info(self, w):
        w.put_smallint(-1)
        w.put_collation(self._collation)

    def write(self, w, val):
        if val is None:
            w.put_int8(-1)
        else:
            if isinstance(val, bytes):
                val = val.decode('utf8')
            w.put_int8(len(val) * 2)
            w.put_int(len(val) * 2)
            w.write_ucs2(val)
            w.put_int(0)


class NVarChar70(object):
    type = XSYBNVARCHAR

    def __init__(self, size):
        if size <= 0 or size > 4000:
            raise DataError('Invalid size for NVARCHAR field')
        self._size = size

    def get_declaration(self):
        return 'NVARCHAR({})'.format(self._size)

    def write_info(self, w):
        w.put_smallint(self._size * 2)
        #w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_smallint(-1)
        else:
            if isinstance(val, bytes):
                val = val.decode('utf8')
            w.put_smallint(len(val) * 2)
            #w.put_smallint(len(val))
            w.write_ucs2(val)


class NVarChar71(NVarChar70):
    type = XSYBNVARCHAR

    def __init__(self, size, collation):
        super(NVarChar71, self).__init__(size)
        self._collation = collation

    def write_info(self, w):
        super(NVarChar71, self).write_info(w)
        w.put_collation(self._collation)


class NText(object):
    def __init__(self, size):
        self._size = size

    def write_info(self, w):
        w.put_int(self._size * 2)

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
        else:
            w.put_int(len(val) * 2)
            w.write_ucs2(val)


class VarBinaryMax(object):
    type = XSYBVARBINARY

    def get_declaration(self):
        return 'VARBINARY(MAX)'

    def write_info(self, w):
        w.put_smallint(-1)

    def write(self, w, val):
        if val is None:
            w.put_int8(-1)
        else:
            w.put_int8(len(val))
            w.put_int(len(val))
            w.write(val)
            w.put_int(0)


class VarBinary(object):
    type = XSYBVARBINARY

    def __init__(self, size):
        self._size = size

    def get_declaration(self):
        return 'VARBINARY({})'.format(self._size)

    def write_info(self, w):
        w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_smallint(-1)
        else:
            w.put_smallint(len(val))
            w.write(val)


class Image(object):
    type = SYBIMAGE

    def get_declaration(self):
        return 'IMAGE'


class BaseDateTime(object):
    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)


class SmallDateTime(BaseDateTime):
    type = SYBDATETIME4

    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    def __init__(self, use_tz):
        self._use_tz = use_tz

    def get_declaration(self):
        return 'SMALLDATETIME'

    def write_info(self, w):
        w.put_byte(4)

    def write(self, w, val):
        w.write(Datetime.encode(value))

    def read(self, r):
        days, time = rdr.unpack(TDS_DATETIME)
        return _applytz(Datetime.decode(days, time), self._use_tz)


class DateTime(object):
    type = SYBDATETIME

    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    def __init__(self, use_tz):
        self._use_tz = use_tz

    def get_declaration(self):
        return 'DATETIME'

    def write_info(self, w):
        w.put_byte(8)

    def write(self, w, val):
        w.write(Datetime.encode(value))

    def read(self, r):
        days, time = rdr.unpack(TDS_DATETIME4)
        return _applytz(Datetime.decode(days, time), self._use_tz)


class DateTimeN(object):
    type = SYBDATETIMN

    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    def __init__(self, size, use_tz):
        assert size in (4, 8)
        self._size = size
        self._use_tz = use_tz

    @classmethod
    def from_stream(self, r, use_tz):
        size = r.get_byte()
        if size not in (4, 8):
            raise InterfaceError('Invalid SYBDATETIMN size', size)
        return DateTimeN(size, use_tz)

    def get_declaration(self):
        if self._size == 8:
            return 'DATETIME'
        elif self._size == 4:
            return 'SMALLDATETIME'

    def write_info(self, w):
        w.put_byte(self._size)

    def write(self, w, val):
        if val is None:
            w.put_byte(0)
        else:
            w.put_byte(8)
            w.write(Datetime.encode(value))

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size == 4:
            days, time = rdr.unpack(TDS_DATETIME4)
        elif size == 8:
            days, time = rdr.unpack(TDS_DATETIME)
        else:
            raise InterfaceError('Invalid datetimn size')
        return _applytz(Datetime.decode(days, time), self._use_tz)


class BaseDateTime73(object):
    _precision_to_len = {
        0: 3,
        1: 3,
        2: 3,
        3: 4,
        4: 4,
        5: 5,
        6: 5,
        7: 5,
        }

    _base_date = datetime(1, 1, 1)

    def _write_time(self, w, t, prec):
        secs = t.hour * 60 * 60 + t.minute * 60 + t.second
        val = (secs * 10 ** 7 + t.microsecond * 10) // (10 ** (7 - prec))
        w.write(struct.pack('<Q', val)[:self._precision_to_len[prec]])

    def _read_time(self, r, size, prec, use_tz):
        time_buf = readall(r, size)
        val = _decode_num(time_buf)
        val *= 10 ** (7 - prec)
        nanoseconds = val * 100
        hours = nanoseconds // 1000000000 // 60 // 60
        nanoseconds -= hours * 60 * 60 * 1000000000
        minutes = nanoseconds // 1000000000 // 60
        nanoseconds -= minutes * 60 * 1000000000
        seconds = nanoseconds // 1000000000
        nanoseconds -= seconds * 1000000000
        return time(hours, minutes, seconds, nanoseconds // 1000, tzinfo=use_tz)

    def _write_date(self, w, value):
        if type(value) == date:
            value = datetime.combine(value, time(0, 0, 0))
        days = (value - self._base_date).days
        buf = struct.pack('<l', days)[:3]
        w.write(buf)

    def _read_date(self, r):
        days = _decode_num(readall(r, 3))
        return (self._base_date + timedelta(days=days)).date()


class MsDate(BaseDateTime73):
    type = SYBMSDATE

    def get_declaration(self):
        return 'DATE'

    def write_info(self, w):
        pass

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            w.put_byte(3)
            self._write_date(w, value)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self._read_date(r)


class MsTime(BaseDateTime73):
    type = SYBMSTIME

    def __init__(self, prec, use_tz=None):
        self._prec = prec
        self._size = self._precision_to_len[prec]
        self._use_tz = use_tz

    @classmethod
    def from_stream(cls, r, use_tz=None):
        prec = r.get_byte()
        return cls(prec, use_tz)

    def get_declaration(self):
        return 'TIME({})'.format(self._prec)

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            if value.tzinfo:
                if not self._use_tz:
                    raise DataError('Timezone-aware datetime is used without specifying use_tz')
                value = value.astimezone(self._use_tz).replace(tzinfo=None)
            w.put_byte(self._size)
            self._write_time(w, value, self._prec)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self._read_time(r, size, self._prec, self._use_tz)


class DateTime2(BaseDateTime73):
    type = SYBMSDATETIME2

    def __init__(self, prec, use_tz):
        self._prec = prec
        self._size = self._precision_to_len[prec] + 3
        self._use_tz = use_tz

    @classmethod
    def from_stream(cls, r, use_tz=None):
        prec = r.get_byte()
        return cls(prec, use_tz)

    def get_declaration(self):
        return 'DATETIME2({})'.format(self._prec)

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            if value.tzinfo:
                if not self._use_tz:
                    raise DataError('Timezone-aware datetime is used without specifying use_tz')
                value = value.astimezone(self._use_tz).replace(tzinfo=None)
            w.put_byte(self._size)
            self._write_time(w, value, self._prec)
            self._write_date(w, value)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        time = self._read_time(r, size - 3, self._prec, self._use_tz)
        date = self._read_date(r)
        return datetime.combine(date, time)


class DateTimeOffset(BaseDateTime73):
    type = SYBMSDATETIMEOFFSET

    def __init__(self, prec):
        self._prec = prec
        self._size = self._precision_to_len[prec] + 5

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    def get_declaration(self):
        return 'DATETIMEOFFSET({})'.format(self._prec)

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            utcoffset = value.utcoffset()
            value = value.astimezone(_utc).replace(tzinfo=None)

            w.put_byte(self._size)
            self._write_time(w, value, self._prec)
            self._write_date(w, value)
            w.put_smallint(int(utcoffset.total_seconds()) // 60)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        time = self._read_time(r, size - 5, self._prec, _utc)
        date = self._read_date(r)
        tz = tzoffset('', r.get_smallint() * 60)
        return datetime.combine(date, time).astimezone(tz)


class MsDecimal(object):
    type = SYBDECIMAL

    _max_size = 33

    _bytes_per_prec = [
        #
        # precision can't be 0 but using a value > 0 assure no
        # core if for some bug it's 0...
        #
        1,
        2, 2, 3, 3, 4, 4, 4, 5, 5,
        6, 6, 6, 7, 7, 8, 8, 9, 9, 9,
        10, 10, 11, 11, 11, 12, 12, 13, 13, 14,
        14, 14, 15, 15, 16, 16, 16, 17, 17, 18,
        18, 19, 19, 19, 20, 20, 21, 21, 21, 22,
        22, 23, 23, 24, 24, 24, 25, 25, 26, 26,
        26, 27, 27, 28, 28, 28, 29, 29, 30, 30,
        31, 31, 31, 32, 32, 33, 33, 33
        ]

    _info_struct = struct.Struct('BBB')

    @property
    def scale(self):
        return self._scale

    @property
    def precision(self):
        return self._prec

    def __init__(self, scale, prec):
        if prec > 38:
            raise DataError('Precision of decimal value is out of range')
        self._scale = scale
        self._prec = prec
        self._size = self._bytes_per_prec[prec]

    @classmethod
    def from_value(cls, value):
        if not (-10 ** 38 + 1 <= value <= 10 ** 38 - 1):
            raise DataError('Decimal value is out of range')
        value = value.normalize()
        _, digits, exp = value.as_tuple()
        if exp > 0:
            scale = 0
            prec = len(digits) + exp
        else:
            scale = -exp
            prec = max(len(digits), scale)
        return cls(scale=scale, prec=prec)

    @classmethod
    def from_stream(cls, r):
        size, prec, scale = r.unpack(cls._info_struct)
        return cls(scale=scale, prec=prec)

    def get_declaration(self):
        return 'DECIMAL({},{})'.format(self._prec, self._scale)

    def write_info(self, w):
        w.pack(self._info_struct, self._size, self._prec, self._scale)

    def write(self, w, value):
        if not isinstance(value, Decimal):
            value = Decimal(value)
        value = value.normalize()
        scale = self._scale
        size = self._size
        w.put_byte(size)
        val = value
        positive = 1 if val > 0 else 0
        w.put_byte(positive)  # sign
        with localcontext() as ctx:
            ctx.prec = 38
            if not positive:
                val *= -1
            size -= 1
            val = val * (10 ** scale)
        for i in range(size):
            w.put_byte(int(val % 256))
            val //= 256
        assert val == 0

    def _decode(self, positive, buf):
        val = _decode_num(buf)
        val = Decimal(val)
        with localcontext() as ctx:
            ctx.prec = 38
            if not positive:
                val *= -1
            val /= 10 ** self._scale
        return val

    def read(self, r):
        size = r.get_byte()
        if size <= 0:
            return None

        positive = r.get_byte()
        buf = readall(r, size - 1)
        return self._decode(positive, buf)


class MsUnique(object):
    type = SYBUNIQUE

    def get_declaration(self):
        return 'UNIQUEIDENTIFIER'

    def write_info(self, w):
        w.put_byte(16)

    def write(self, w, value):
        if value is None:
            w.put_byte(-1)
        else:
            w.put_byte(16)
            w.write(value.bytes_le)


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
        self._reader = _TdsReader(self, tds.emul_little_endian)
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
        self.use_tz = tds._login.use_tz
        self._spid = 0

    def is_dead(self):
        return self.state == TDS_DEAD

    def is_connected(self):
        return self._transport.is_connected()

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
                #tds_mutex_unlock(self.wire_mtx)
            else:
                logger.error('logic error: cannot chage query state from {0} to {1}'.
                             format(state_names[prior_state], state_names[state]))
        elif state == TDS_READING:
            # transition to READING are valid only from PENDING
            #if tds_mutex_trylock(self.wire_mtx):
            #    return self.state
            if self.state != TDS_PENDING:
                #tds_mutex_unlock(self.wire_mtx)
                logger.error('logic error: cannot change query state from {0} to {1}'.
                             format(state_names[prior_state], state_names[state]))
            else:
                self.state = state
        elif state == TDS_IDLE:
            if prior_state == TDS_DEAD:
                logger.error('logic error: cannot change query state from {0} to {1}'.
                             format(state_names[prior_state], state_names[state]))
            #elif prior_state in (TDS_READING, TDS_QUERYING):
            #    tds_mutex_unlock(self.wire_mtx)
            self.state = state
        elif state == TDS_DEAD:
            #if prior_state in (TDS_READING, TDS_QUERYING):
            #    tds_mutex_unlock(self.wire_mtx)
            self.state = state
        elif state == TDS_QUERYING:
            #if tds_mutex_trylock(self.wire_mtx):
            #    return self.state
            if self.state == TDS_DEAD:
                #tds_mutex_unlock(self.wire_mtx)
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            elif self.state != TDS_IDLE:
                #tds_mutex_unlock(self.wire_mtx)
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            else:
                self.rows_affected = TDS_NO_COUNT
                self.internal_sp_called = 0
                self.state = state
        else:
            assert False
        return self.state

    def state_context(self, state):
        return _StateContext(self, state)

    def query_flush_packet(self):
        # TODO depend on result ??
        self.set_state(TDS_PENDING)
        self._writer.flush()

    def _write_nvarchar_max(self, w, val):
        if val is None:
            w.put_int8(-1)
        else:
            w.put_int8(len(val) * 2)
            w.put_int(len(val) * 2)
            w.write_ucs2(val)
            w.put_int(0)

    def _write_nvarchar(self, w, val):
        if val is None:
            w.put_smallint(-1)
        else:
            w.put_smallint(len(val) * 2)
            w.write_ucs2(val)

    def make_param(self, name, value):
        column = _Column()
        column.column_name = name
        column.flags = 0
        if isinstance(value, output):
            column.flags |= fByRefValue
            value = value.value
        if value is default:
            column.flags = fDefaultValue
            value = None
        column.value = value
        if value is None:
            if IS_TDS71_PLUS(self):
                column.type = NVarChar71(1, self.conn.collation)
            else:
                column.type = NVarChar70(1)
        elif isinstance(value, bool):
            column.type = Bit()
        elif isinstance(value, six.integer_types):
            if -2 ** 31 <= value <= 2 ** 31 - 1:
                column.type = Int()
            elif -2 ** 63 <= value <= 2 ** 63 - 1:
                column.type = BigInt()
            elif -10 ** 38 + 1 <= value <= 10 ** 38 - 1:
                column.type = MsDecimal(0, 38)
            else:
                raise DataError('Numeric value out or range')
        elif isinstance(value, float):
            column.type = FloatN()
        elif isinstance(value, Binary):
            size = len(value)
            if size > 8000:
                if IS_TDS72_PLUS(tds):
                    column.type = VarBinaryMax()
                else:
                    column.type = Image()
            else:
                column.type = VarBinary(size)
        elif isinstance(value, six.string_types + (six.binary_type,)):
            size = len(value)
            if size == 0:
                size = 1
            if size > 4000:
                if IS_TDS72_PLUS(self):
                    column.type = NVarCharMax(self.conn.collation)
                else:
                    column.type = NText()
            else:
                if IS_TDS71_PLUS(self):
                    column.type = NVarChar71(size, self.conn.collation)
                else:
                    column.type = NVarChar70(size)
        elif isinstance(value, datetime):
            if IS_TDS73_PLUS(self):
                if value.tzinfo and not self.use_tz:
                    column.type = DateTimeOffset(6)
                else:
                    column.type = DateTime2(6, self.use_tz)
            else:
                column.type = DateTimeN()
        elif isinstance(value, date):
            if IS_TDS73_PLUS(self):
                column.type = MsDate()
            else:
                column.type = DateTimeN()
        elif isinstance(value, time):
            if not IS_TDS73_PLUS(self):
                raise DataError('Time type is not supported on MSSQL 2005 and lower')
            column.type = MsTime(6, self.use_tz)
        elif isinstance(value, Decimal):
            column.type = MsDecimal.from_value(value)
        elif isinstance(value, uuid.UUID):
            column.type = MsUnique()
        else:
            raise DataError('Parameter type is not supported: {0}'.format(repr(value)))
        return column

    def _convert_params(self, parameters):
        if isinstance(parameters, dict):
            return [self.make_param(name, value) for name, value in parameters.items()]
        else:
            params = []
            for parameter in parameters:
                if isinstance(parameter, _Column):
                    params.append(parameter)
                else:
                    params.append(self.make_param('', parameter))
            return params

    def _submit_rpc(self, rpc_name, params, flags):
        self.cur_dyn = None
        w = self._writer
        if IS_TDS7_PLUS(self):
            w.begin_packet(TDS_RPC)
            self._START_QUERY()
            if IS_TDS71_PLUS(self) and isinstance(rpc_name, InternalProc):
                w.put_smallint(-1)
                w.put_smallint(rpc_name.proc_id)
            else:
                w.put_smallint(len(rpc_name))
                w.write_ucs2(rpc_name)
            #
            # TODO support flags
            # bit 0 (1 as flag) in TDS7/TDS5 is "recompile"
            # bit 1 (2 as flag) in TDS7+ is "no metadata" bit this will prevent sending of column infos
            #
            w.put_usmallint(flags)
            params = self._convert_params(params)
            for param in params:
                w.put_byte(len(param.column_name))
                w.write_ucs2(param.column_name)
                #
                # TODO support other flags (use defaul null/no metadata)
                # bit 1 (2 as flag) in TDS7+ is "default value" bit
                # (what's the meaning of "default value" ?)
                #
                w.put_byte(param.flags)
                # FIXME: column_type is wider than one byte.  Do something sensible, not just lop off the high byte.
                w.put_byte(param.type.type)
                param.type.write_info(w)
                param.type.write(w, param.value)
            #self.query_flush_packet()
        elif IS_TDS5_PLUS(self):
            w.begin_packet(TDS_NORMAL)
            w.put_byte(TDS_DBRPC_TOKEN)
            # TODO ICONV convert rpc name
            w.put_smallint(len(rpc_name) + 3)
            w.put_byte(len(rpc_name))
            w.write(rpc_name)
            # TODO flags
            w.put_smallint(2 if params else 0)

            if params:
                self.put_params(params, TDS_PUT_DATA_USE_NAME)

            # send it
            #self.query_flush_packet()
        else:
            # emulate it for TDS4.x, send RPC for mssql
            return tds_send_emulated_rpc(self, rpc_name, params)

    def submit_rpc(self, rpc_name, params=(), flags=0):
        with self.state_context(TDS_QUERYING):
            self._submit_rpc(rpc_name, params, flags)
            self.query_flush_packet()

    def submit_query(self, query, params=(), flags=0):
        logger.info('submit_query(%s, %s)', query, params)
        if not query:
            raise ProgrammingError('Empty query is not allowed')

        with self.state_context(TDS_QUERYING):
            self.res_info = None
            w = self._writer
            if IS_TDS50(self):
                new_query = None
                # are there '?' style parameters ?
                if tds_next_placeholder(query):
                    new_query = tds5_fix_dot_query(query, params)
                    query = new_query

                w.begin_packet(TDS_NORMAL)
                w.put_byte(TDS_LANGUAGE_TOKEN)
                # TODO ICONV use converted size, not input size and convert string
                w.put_int(len(query) + 1)
                w.put_byte(1 if params else 0)  # 1 if there are params, 0 otherwise
                w.write(self, query)
                if params:
                    # add on parameters
                    self.put_params(params, TDS_PUT_DATA_USE_NAME if params.columns[0].column_name else 0)
            elif not IS_TDS7_PLUS(self) or not params:
                w.begin_packet(TDS_QUERY)
                self._START_QUERY()
                w.write_ucs2(query)
            else:
                params = self._convert_params(params)
                param_definition = ','.join(
                    '{0} {1}'.format(p.column_name, p.type.get_declaration())
                    for p in params)
                self._submit_rpc(SP_EXECUTESQL,
                            [query, param_definition] + params, 0)
                self.internal_sp_called = TDS_SP_EXECUTESQL
            self.query_flush_packet()

    def _put_cancel(self):
        self._writer.begin_packet(TDS_CANCEL)
        self._writer.flush()
        self.in_cancel = 1

    def send_cancel(self):
        if TDS_MUTEX_TRYLOCK(self.wire_mtx):
            # TODO check
            # signal other socket
            raise NotImplementedError
            #tds_conn(tds).s_signal.send((void*) &tds, sizeof(tds))
            return TDS_SUCCESS

        logger.debug("send_cancel: %sin_cancel and %sidle".format(
                    ('' if self.in_cancel else "not "), ('' if self.state == TDS_IDLE else "not ")))

        # one cancel is sufficient
        if self.in_cancel or self.state == TDS_IDLE:
            TDS_MUTEX_UNLOCK(self.wire_mtx)
            return TDS_SUCCESS

        self.res_info = None
        rc = self._put_cancel()
        TDS_MUTEX_UNLOCK(self.wire_mtx)

        return rc

    _begin_tran_struct_72 = struct.Struct('<HBB')

    def submit_begin_tran(self, isolation_level=0):
        logger.debug('submit_begin_tran()')
        if IS_TDS72_PLUS(self):
            if self.set_state(TDS_QUERYING) != TDS_QUERYING:
                raise Exception('TDS_FAIL')

            w = self._writer
            w.begin_packet(TDS7_TRANS)
            self._start_query()
            w.pack(self._begin_tran_struct_72,
                   5, # TM_BEGIN_XACT
                   isolation_level,
                   0,  # new transaction name
                   )
            self.query_flush_packet()
        else:
            self.submit_query("BEGIN TRANSACTION")

    _commit_rollback_tran_struct72_hdr = struct.Struct('<HBB')
    _continue_tran_struct72 = struct.Struct('<BB')

    def submit_rollback(self, cont, isolation_level=0):
        logger.debug('submit_rollback(%s, %s)', id(self), cont)
        if IS_TDS72_PLUS(self):
            if self.set_state(TDS_QUERYING) != TDS_QUERYING:
                raise Exception('TDS_FAIL')

            w = self._writer
            w.begin_packet(TDS7_TRANS)
            self._start_query()
            flags = 0
            if cont:
                flags |= 1
            w.pack(self._commit_rollback_tran_struct72_hdr,
                   8,  # TM_ROLLBACK_XACT
                   0,  # transaction name
                   flags,
                   )
            if cont:
                w.pack(self._continue_tran_struct72,
                       isolation_level,
                       0,  # new transaction name
                       )
            self.query_flush_packet()
        else:
            self.submit_query("IF @@TRANCOUNT > 0 ROLLBACK BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 ROLLBACK")

    def submit_commit(self, cont, isolation_level=0):
        logger.debug('submit_commit(%s)', cont)
        if IS_TDS72_PLUS(self):
            if self.set_state(TDS_QUERYING) != TDS_QUERYING:
                raise Exception('TDS_FAIL')

            w = self._writer
            w.begin_packet(TDS7_TRANS)
            self._start_query()
            flags = 0
            if cont:
                flags |= 1
            w.pack(self._commit_rollback_tran_struct72_hdr,
                   7,  # TM_COMMIT_XACT
                   0,  # transaction name
                   flags,
                   )
            if cont:
                w.pack(self._continue_tran_struct72,
                       isolation_level,
                       0,  # new transaction name
                       )
            self.query_flush_packet()
        else:
            self.submit_query("IF @@TRANCOUNT > 1 COMMIT BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 COMMIT")

    def _START_QUERY(self):
        if IS_TDS72_PLUS(self):
            self._start_query()

    _tds72_query_start = struct.Struct('<IIHQI')

    def _start_query(self):
        w = self._writer
        w.pack(_TdsSession._tds72_query_start,
            0x16,  # total length
            0x12,  # length
            2,  # type
            self.conn.tds72_transaction,
            1,  # request count
            )


class _StateContext(object):
    def __init__(self, session, state):
        self._session = session
        self._state = state

    def __enter__(self):
        if self._session.set_state(self._state) != self._state:
            raise Error("Couldn't switch to state")
        return self

    def __exit__(self, type, value, traceback):
        if type is not None:
            if self._session.state != TDS_DEAD:
                self._session.set_state(TDS_IDLE)


class _TdsSocket(object):
    def __init__(self, login):
        self._is_connected = False
        self._bufsize = login.blocksize
        self.login = None
        self.int_handler = None
        self.msg_handler = None
        self.env = _TdsEnv()
        self.collation = None
        self.tds72_transaction = 0
        self.authentication = None
        self._mars_enabled = False
        tds_conn(self).s_signal = tds_conn(self).s_signaled = None
        self.emul_little_endian = True
        self.chunk_handler = MemoryChunkedHandler()
        self._login = login
        self._main_session = _TdsSession(self, self)

        # Jeff's hack, init to no timeout
        self.query_timeout = login.connect_timeout if login.connect_timeout else login.query_timeout
        self._sock = None
        import socket
        if hasattr(socket, 'socketpair'):
            tds_conn(self).s_signal, tds_conn(self).s_signaled = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.tds_version = login.tds_version
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
            err = None
            for host in login.load_balancer.choose():
                try:
                    tds_open_socket(self, host, login.port, connect_timeout)
                except socket.error as e:
                    err = LoginError("Cannot connect to server '{0}': {1}".format(host, e), e)
                    continue
                try:
                    from .login import tds_login
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
                        tds._main_session.submit_query(''.join(q))
                        tds_process_simple_query(tds._main_session)
                except Exception as e:
                    self._sock.close()
                    err = e
                    #raise
                    continue
                break
            else:
                raise err
        except Exception:
            if tds_conn(self).s_signal is not None:
                tds_conn(self).s_signal.close()
            if tds_conn(self).s_signaled is not None:
                tds_conn(self).s_signaled.close()
            raise

    def _setup_smp(self):
        from .smp import SmpManager
        self._smp_manager = SmpManager(self)
        self._main_session = _TdsSession(self, self._smp_manager.create_session())

    @property
    def mars_enabled(self):
        return self._mars_enabled

    @property
    def main_session(self):
        return self._main_session

    def create_session(self):
        return _TdsSession(self, self._smp_manager.create_session())

    def read(self, size):
        r, _, _ = select.select([self._sock], [], [], self.query_timeout)
        if not r:
            raise TimeoutError('Timeout')
        buf = self._sock.recv(size)
        if len(buf) == 0:
            self.close()
            raise Error('Server closed connection')
        return buf

    def send(self, data, final):
        return self._write(data, final)

    def _write(self, data, final):
        try:
            pos = 0
            while pos < len(data):
                _, w, _ = select.select([], [self._sock], [], self.query_timeout)
                if not w:
                    raise TimeoutError('Timeout')
                flags = 0
                if hasattr(socket, 'MSG_NOSIGNAL'):
                    flags |= socket.MSG_NOSIGNAL
                if not final:
                    if hasattr(socket, 'MSG_MORE'):
                        flags |= socket.MSG_MORE
                nput = self._sock.send(data[pos:], flags)
                pos += nput
            if final and USE_CORK:
                self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 0)
                self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 1)
        except:
            self.close()
            raise

    def is_connected(self):
        return self._is_connected

    def close(self):
        self._is_connected = False
        if self._sock is not None:
            self._sock.close()
        if hasattr(self, '_smp_manager'):
            self._smp_manager._transport_closed()
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
            msg = s.recv(16 * 1024 - 1)
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


def _applytz(dt, tz):
    if not tz:
        return dt
    dt = dt.replace(tzinfo=tz)
    return dt


class DefaultHandler(object):
    @staticmethod
    def _tds72_get_varmax(tds, curcol, codec):
        r = tds._reader
        size = r.get_int8()

        # NULL
        if size == -1:
            return None

        decoder = None
        if codec:
            decoder = codec.incrementaldecoder()
            chunk_handler = MemoryStrChunkedHandler()
        else:
            chunk_handler = tds.chunk_handler
        chunk_handler.begin(curcol, size)
        while True:
            chunk_len = r.get_int()
            if chunk_len <= 0:
                if decoder:
                    val = decoder.decode(b'', True)
                    chunk_handler.new_chunk(val)
                return chunk_handler.end()
            left = chunk_len
            while left:
                val = r.read(left)
                left -= len(val)
                if decoder:
                    val = decoder.decode(val)
                chunk_handler.new_chunk(val)

    @staticmethod
    def from_python(tds, col, value):
        if value is None:
            col.column_type = XSYBVARCHAR
            col.column_size = 1
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        elif isinstance(value, six.integer_types):
            col.column_type = SYBINTN
            if -2 ** 31 <= value <= 2 ** 31 - 1:
                col.column_size = 4
            elif -2 ** 63 <= value <= 2 ** 63 - 1:
                col.column_size = 8
            else:
                raise DataError('Numeric value out or range')
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        elif isinstance(value, float):
            col.column_type = SYBFLTN
            col.column_size = 8
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        elif isinstance(value, Binary):
            if len(value) > 8000:
                if IS_TDS72_PLUS(tds):
                    col.column_type = XSYBVARBINARY
                    col.column_varint_size = 8  # nvarchar(max)
                else:
                    col.column_type = SYBIMAGE
                    col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            else:
                col.column_type = XSYBVARBINARY
                col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            col.column_size = len(value)
        elif isinstance(value, six.string_types + (six.binary_type,)):
            if len(value) > 4000:
                if IS_TDS72_PLUS(tds):
                    col.column_type = XSYBNVARCHAR
                    col.column_varint_size = 8  # nvarchar(max)
                else:
                    col.column_type = SYBNTEXT
                    col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            else:
                col.column_type = XSYBNVARCHAR
                col.column_varint_size = tds_get_varint_size(tds, col.column_type)
            col.column_size = len(value) * 2
            col.char_codec = ucs2_codec
        elif isinstance(value, uuid.UUID):
            col.column_type = SYBUNIQUE
            col.column_size = 16
            col.column_varint_size = tds_get_varint_size(tds, col.column_type)
        return value

    @staticmethod
    def get_declaration(tds, col):
        max_len = 8000 if IS_TDS7_PLUS(tds) else 255
        t = col.column_type
        if t in (XSYBCHAR, SYBCHAR):
            return "CHAR(%d)" % col.size
        elif t in (SYBVARCHAR, XSYBVARCHAR):
            if col.column_varint_size == 8:
                return "VARCHAR(MAX)"
            else:
                return "VARCHAR(%d)" % col.column_size
        elif t == SYBINT1:
            return "TINYINT"
        elif t == SYBINT2:
            return "SMALLINT"
        elif t == SYBINT4 or t == SYBINTN and col.column_size == 4:
            return "INT"
        elif t == SYBINT8 or t == SYBINTN and col.column_size == 8:
            # TODO even for Sybase ??
            return "BIGINT"
        elif t == SYBFLT8 or t == SYBFLTN and col.column_size == 8:
            return "FLOAT"
        elif t == SYBBIT:
            return "BIT"
        elif t == SYBTEXT:
            return "TEXT"
        elif t == (SYBLONGBINARY,  # TODO correct ??
                   SYBIMAGE):
            return "IMAGE"
        elif t == SYBMONEY4:
            return "SMALLMONEY"
        elif t == SYBMONEY:
            return "MONEY"
        elif t == SYBREAL:
            return "REAL"
        elif t in (SYBBINARY, XSYBBINARY):
            return "BINARY(%d)" % min(size, max_len)
        elif t in (SYBVARBINARY, XSYBVARBINARY):
            if col.column_varint_size == 8:
                return "VARBINARY(MAX)"
            else:
                return "VARBINARY(%u)" % min(col.column_size, max_len)
        elif t == SYBUNIQUE:
            if IS_TDS7_PLUS(tds):
                return "UNIQUEIDENTIFIER"
        elif t == SYBNTEXT:
            if IS_TDS7_PLUS(tds):
                return "NTEXT"
        elif t in (SYBNVARCHAR, XSYBNVARCHAR):
            if col.column_varint_size == 8:
                return "NVARCHAR(MAX)"
            elif IS_TDS7_PLUS(tds):
                return "NVARCHAR(%u)" % max(col.column_size // 2, 1)
        elif t == XSYBNCHAR:
            if IS_TDS7_PLUS(tds):
                return "NCHAR(%u)" % min(col.column_size // 2, 4000)
        elif t == SYBVARIANT:
            if IS_TDS7_PLUS(tds):
                return "SQL_VARIANT"
        # nullable types should not occur here...
        elif t in (SYBMONEYN, SYBDATETIMN, SYBBITN):
            assert False
            # TODO...
        else:
            raise Exception("Unknown type %d", t)

    @staticmethod
    def put_info(tds, col):
        w = tds._writer
        size = tds_fix_column_size(tds, col)
        vs = col.column_varint_size
        if vs == 0:
            pass
        elif vs == 1:
            w.put_byte(size)
        elif vs == 2:
            w.put_smallint(size)
        elif vs in (4, 5):
            w.put_int(size)
        elif vs == 8:
            w.put_smallint(-1)

        # TDS7.1 output collate information
        if IS_TDS71_PLUS(tds) and is_collate_type(col.column_type):
            w.put_collation(tds.conn.collation)

    @staticmethod
    def put_data(tds, curcol):
        w = tds._writer
        #logger.debug("tds_data_put")
        if curcol.value is None:
            #logger.debug("tds_data_put: null param")
            vs = curcol.column_varint_size
            if vs == 5:
                w.put_int(0)
            elif vs == 4:
                w.put_int(-1)
            elif vs == 2:
                w.put_smallint(-1)
            elif vs == 8:
                w.put_int8(-1)
            else:
                assert curcol.column_varint_size
                # FIXME not good for SYBLONGBINARY/SYBLONGCHAR (still not supported)
                w.put_byte(0)
            return

        size = tds_fix_column_size(tds, curcol)

        # convert string if needed
        value = curcol.value
        if curcol.char_codec:
            # we need to convert data before
            # TODO this can be a waste of memory...
            value = tds_convert_string(tds, curcol.char_codec, value)
            colsize = len(value)
        else:
            colsize = curcol.column_size

        #
        # TODO here we limit data sent with MIN, should mark somewhere
        # and inform client ??
        # Test proprietary behavior
        #
        if IS_TDS7_PLUS(tds):
            #logger.debug("tds_data_put: not null param varint_size = %d",
            #             curcol.column_varint_size)

            vs = curcol.column_varint_size
            if vs == 8:
                w.put_int8(colsize)
                w.put_int(colsize)
            elif vs == 4:  # It's a BLOB...
                colsize = min(colsize, size)
                # mssql require only size
                w.put_int(colsize)
            elif vs == 2:
                colsize = min(colsize, size)
                w.put_smallint(colsize)
            elif vs == 1:
                w.put_byte(size)
            elif vs == 0:
                # TODO should be column_size
                colsize = tds_get_size_by_type(curcol.column_type)

            # put real data
            column_type = curcol.column_type
            if column_type == SYBINTN and size == 4 or column_type == SYBINT4:
                w.put_int(value)
            elif column_type == SYBINTN and size == 8 or column_type == SYBINT8:
                w.put_int8(value)
            elif column_type in (XSYBNVARCHAR, XSYBNCHAR):
                w.write(value)
            elif column_type in (XSYBVARBINARY, XSYBBINARY):
                w.write(value)
            elif column_type == SYBFLTN and size == 8 or column_type == SYBFLT8:
                w.write(_SYBFLT8_STRUCT.pack(value))
            elif column_type == SYBNTEXT:
                w.write(value)
            elif column_type == SYBUNIQUE:
                w.write(value.bytes_le)
            else:
                raise Exception('not implemented')
            # finish chunk for varchar/varbinary(max)
            if curcol.column_varint_size == 8 and colsize:
                w.put_int(0)
        else:
            raise Exception('not implemented')

_SYBFLT8_STRUCT = struct.Struct('d')
_ubyte_struct = struct.Struct('B')
_sbyte_struct = struct.Struct('b')
_sshort_struct = struct.Struct('<h')
_slong_struct = struct.Struct('<l')
_slong8_struct = struct.Struct('<q')
_flt4_struct = struct.Struct('f')
_money8_struct = struct.Struct('<lL')
_simple_types = {SYBVARCHAR, SYBCHAR, SYBTEXT, SYBBINARY,
                 SYBNVARCHAR, XSYBVARCHAR, XSYBNVARCHAR, XSYBCHAR, XSYBNCHAR,
                 XSYBVARBINARY, XSYBBINARY, SYBVARBINARY}


def to_python(tds, data, type, length):
    #logger.debug("to_python()")

    if type == SYBBIT or type == SYBBITN:
        return bool(_ubyte_struct.unpack(data)[0])

    elif type == SYBINT1 or type == SYBINTN and length == 1:
        return _sbyte_struct.unpack(data)[0]

    elif type == SYBINT2 or type == SYBINTN and length == 2:
        return _sshort_struct.unpack(data)[0]

    elif type == SYBINT4 or type == SYBINTN and length == 4:
        return _slong_struct.unpack(data)[0]

    elif type == SYBINT8 or type == SYBINTN and length == 8:
        return _slong8_struct.unpack(data)[0]

    elif type == SYBREAL or type == SYBFLTN and length == 4:
        return _flt4_struct.unpack(data)[0]

    elif type == SYBFLT8 or type == SYBFLTN and length == 8:
        return _SYBFLT8_STRUCT.unpack(data)[0]

    elif type in (SYBMONEY, SYBMONEY4, SYBMONEYN):
        if length == 8:
            hi, lo = _money8_struct.unpack(data)
            val = hi * (2 ** 32) + lo
        elif length == 4:
            val, = _slong_struct.unpack(data)
        else:
            raise Exception('unsupported size of money type')
        val = Decimal(val) / 10000
        return val

    #elif type in (SYBVARCHAR, SYBCHAR, SYBTEXT, SYBBINARY,\
    #        SYBNVARCHAR, XSYBVARCHAR, XSYBNVARCHAR, XSYBCHAR, XSYBNCHAR,\
    #        XSYBVARBINARY, XSYBBINARY, SYBVARBINARY):
    elif type in _simple_types:

        return data

    elif type == SYBUNIQUE:
        return uuid.UUID(bytes_le=data)

    else:
        raise Exception('unknown type {0}'.format(type))


if sys.version_info[0] >= 3:
    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + val, reversed(buf), 0)
else:
    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + ord(val), reversed(buf), 0)


class NumericHandler(object):
    MAX_NUMERIC = 33

    @staticmethod
    def ms_parse_numeric(positive, buf, scale):
        val = _decode_num(buf)
        val = Decimal(val)
        with localcontext() as ctx:
            ctx.prec = 38
            if not positive:
                val *= -1
            val /= 10 ** scale
        return val

    @classmethod
    def get_data(cls, tds, curcol):
        r = tds._reader
        colsize = r.get_byte()

        # set NULL flag in the row buffer
        if colsize <= 0:
            return None

        else:
            raise Exception('not supported')

    tds_numeric_bytes_per_prec = [
        #
        # precision can't be 0 but using a value > 0 assure no
        # core if for some bug it's 0...
        #
        1,
        2, 2, 3, 3, 4, 4, 4, 5, 5,
        6, 6, 6, 7, 7, 8, 8, 9, 9, 9,
        10, 10, 11, 11, 11, 12, 12, 13, 13, 14,
        14, 14, 15, 15, 16, 16, 16, 17, 17, 18,
        18, 19, 19, 19, 20, 20, 21, 21, 21, 22,
        22, 23, 23, 24, 24, 24, 25, 25, 26, 26,
        26, 27, 27, 28, 28, 28, 29, 29, 30, 30,
        31, 31, 31, 32, 32, 33, 33, 33
        ]

    @staticmethod
    def from_python(tds, col, value):
        if not (-10 ** 38 + 1 <= value <= 10 ** 38 - 1):
            raise DataError('Decimal value is out of range')
        value = value.normalize()
        col.column_type = SYBDECIMAL
        _, digits, exp = value.as_tuple()
        if exp > 0:
            col.column_scale = 0
            col.column_prec = len(digits) + exp
        else:
            col.column_scale = -exp
            col.column_prec = max(len(digits), col.column_scale)
        if col.column_prec > 38:
            raise DataError('Precision of decimal value is out of range')
        return value

    @staticmethod
    def get_declaration(tds, col):
        if col.column_type == SYBNUMERIC:
            return "NUMERIC(%d,%d)" % (col.column_prec, col.column_scale)
        elif col.column_type == SYBDECIMAL:
            return "DECIMAL(%d,%d)" % (col.column_prec, col.column_scale)

    @staticmethod
    def put_info(tds, col):
        w = tds._writer
        w.put_byte(NumericHandler.tds_numeric_bytes_per_prec[col.column_prec])
        w.put_byte(col.column_prec)
        w.put_byte(col.column_scale)

    @staticmethod
    def put_data(tds, col):
        w = tds._writer
        scale = col.column_scale
        size = NumericHandler.tds_numeric_bytes_per_prec[col.column_prec]
        w.put_byte(size)
        val = col.value
        positive = 1 if val > 0 else 0
        w.put_byte(positive)  # sign
        with localcontext() as ctx:
            ctx.prec = 38
            if not positive:
                val *= -1
            size -= 1
            val = val * (10 ** scale)
        for i in range(size):
            w.put_byte(int(val % 256))
            val //= 256
        assert val == 0


#
# This strange type has following structure
# 0 len (int32) -- NULL
# len (int32), type (int8), data -- ints, date, etc
# len (int32), type (int8), 7 (int8), collation, column size (int16) -- [n]char, [n]varchar, binary, varbinary
# BLOBS (text/image) not supported
#
class VariantHandler(object):
    @staticmethod
    def get_data(tds, curcol):
        r = tds._reader
        colsize = r.get_int()

        # NULL
        try:
            if colsize < 2:
                r.skip(colsize)
                return None

            type = r.get_byte()
            info_len = r.get_byte()
            colsize -= 2
            if info_len > colsize:
                raise Exception('TDS_FAIL')
            if is_collate_type(type):
                if Collation.wire_size > info_len:
                    raise Exception('TDS_FAIL')
                curcol.collation = collation = r.get_collation()
                colsize -= Collation.wire_size
                info_len -= Collation.wire_size
                curcol.char_codec = ucs2_codec if is_unicode_type(type) else\
                    collation.get_codec()
            # special case for numeric
            if is_numeric_type(type):
                if info_len != 2:
                    raise Exception('TDS_FAIL')
                curcol.precision = r.get_byte()
                curcol.scale = scale = r.get_byte()
                colsize -= 2
                # FIXME check prec/scale, don't let server crash us
                if colsize > NumericHandler.MAX_NUMERIC:
                    raise Exception('TDS_FAIL')
                positive = r.get_byte()
                buf = readall(r, colsize - 1)
                return NumericHandler.ms_parse_numeric(positive, buf, scale)
            varint = 0 if type == SYBUNIQUE else tds_get_varint_size(tds, type)
            if varint != info_len:
                raise Exception('TDS_FAIL')
            if varint == 0:
                size = tds_get_size_by_type(type)
            elif varint == 1:
                size = r.get_byte()
            elif varint == 2:
                size = r.get_smallint()
            else:
                raise Exception('TDS_FAIL')
            colsize -= info_len
            if colsize:
                if curcol.char_codec:
                    data = tds_get_char_data(tds, colsize, curcol)
                else:
                    data = readall(r, colsize)
            colsize = 0
            return to_python(tds, data, type, colsize)
        except:
            r.skip(colsize)
            raise


def gen_get_varint_size():
    table = '''\
name	vendor	varint	fixed	nullable	variable	blob	numeric	unicode	ascii	size	nullable type
SYB5INT8	SYB	0	1	0	0	0	0	0	0	8	SYBINTN
SYBBINARY	ALL	1	0	1	1	0	0	0	0	-1	0
SYBBIT	ALL	0	1	0	0	0	0	0	0	1	SYBBITN
SYBBITN	MS	1	0	1	0	0	0	0	0	1	0	# Sybase bit is not nullable
SYBBLOB	SYB	??	0	1	1	1	0	Depend	Depend	-1	0
SYBBOUNDARY	SYB	1	0	1	1	0	0	0	1	-1	0
SYBCHAR	ALL	1	0	1	1	0	0	0	1	-1	0
SYBDATE	SYB	0	1	0	0	0	0	0	0	4	SYBDATEN
SYBDATEN	SYB	1	0	1	0	0	0	0	0	4	0
SYBDATETIME	ALL	0	1	0	0	0	0	0	0	8	SYBDATETIMN
SYBDATETIME4	ALL	0	1	0	0	0	0	0	0	4	SYBDATETIMN
SYBDATETIMN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBMSDATE	MS	1	0	1	0	0	0	0	0	4	0
SYBMSTIME	MS	1	0	1	0	0	0	0	0	-1	0
SYBMSDATETIME2	MS	1	0	1	0	0	0	0	0	-1	0
SYBMSDATETIMEOFFSET	MS	1	0	1	0	0	0	0	0	-1	0
SYBDECIMAL	ALL	1	0	1	0	0	1	0	0	-1	0
SYBFLT8	ALL	0	1	0	0	0	0	0	0	8	SYBFLTN
SYBFLTN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBIMAGE	ALL	4	0	1	1	1	0	0	0	-1	0
SYBINT1	ALL	0	1	0	0	0	0	0	0	1	SYBINTN
SYBINT2	ALL	0	1	0	0	0	0	0	0	2	SYBINTN
SYBINT4	ALL	0	1	0	0	0	0	0	0	4	SYBINTN
SYBINT8	MS	0	1	0	0	0	0	0	0	8	SYBINTN
SYBINTERVAL	SYB	0	1	0	0	0	0	0	0	8	0
SYBINTN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBLONGBINARY	SYB	5	0	1	1	1	0	Depend	Depend	-1	0
SYBLONGCHAR	SYB	5	0	1	1	1	0	??	??	-1	0
SYBMONEY	ALL	0	1	0	0	0	0	0	0	8	SYBMONEYN
SYBMONEY4	ALL	0	1	0	0	0	0	0	0	4	SYBMONEYN
SYBMONEYN	ALL	1	0	1	0	0	0	0	0	-1	0
SYBMSUDT	MS	??	0	1	1	??	0	??	??	-1	0
SYBMSXML	MS	8	0	1	1	1	0	1	0	-1	0
SYBNTEXT	MS	4	0	1	1	1	0	1	0	-1	0
SYBNUMERIC	ALL	1	0	1	0	0	1	0	0	-1	0
SYBNVARCHAR	MS	??	0	1	1	0	0	1	0	-1	0	# Same as XSYBNVARCHAR ??
SYBREAL	ALL	0	1	0	0	0	0	0	0	4	SYBFLTN
SYBSENSITIVITY	SYB	1	0	1	1	0	0	0	1	-1	0
SYBSINT1	SYB	0	1	0	0	0	0	0	0	1	0
SYBTEXT	ALL	4	0	1	1	1	0	0	1	-1	0
SYBTIME	SYB	0	1	0	0	0	0	0	0	4	SYBTIMEN
SYBTIMEN	SYB	1	0	1	0	0	0	0	0	4	0
SYBUINT1	SYB	0	1	0	0	0	0	0	0	1	SYBUINTN
SYBUINT2	SYB	0	1	0	0	0	0	0	0	2	SYBUINTN
SYBUINT4	SYB	0	1	0	0	0	0	0	0	4	SYBUINTN
SYBUINT8	SYB	0	1	0	0	0	0	0	0	8	SYBUINTN
SYBUINTN	SYB	1	0	1	0	0	0	0	0	-1	0
SYBUNIQUE	MS	1	0	1	0	0	0	0	0	16	0	# have size but is nullable
SYBUNITEXT	SYB	4	0	1	1	1	0	1	0	-1	0	# UTF-16
SYBVARBINARY	ALL	1	0	1	1	0	0	0	0	-1	0
SYBVARCHAR	ALL	1	0	1	1	0	0	0	1	-1	0
SYBVARIANT	MS	4	0	1	1	0	0	Depend	Depend	-1	0	# varint ok ?
SYBVOID	MS ??	0	1	0	0	0	0	0	0	0	0
SYBXML	SYB	4	0	1	1	1	0	??	??	-1	0
XSYBBINARY	MS	2	0	1	1	0	0	0	0	-1	0
XSYBCHAR	MS	2	0	1	1	0	0	0	1	-1	0
XSYBNCHAR	MS	2	0	1	1	0	0	1	0	-1	0
XSYBNVARCHAR	MS	2	0	1	1	0	0	1	0	-1	0
XSYBVARBINARY	MS	2	0	1	1	0	0	0	0	-1	0
XSYBVARCHAR	MS	2	0	1	1	0	0	0	1	-1	0

# XSYBVARCHAR blob se TDS9 ??
# char if ascii or unicode
# there are some type that allow size 0 or a constants (SYBDATEN, SYBUNIQUE)
# some type (BITN, DATEN, UNIQUE, MSDATE) have size but are nullable
# tds_get_conversion_type from nullable to not nullable

# $Id: types.txt,v 1.5 2011/05/12 19:40:57 freddy77 Exp $
'''
    lines = list(map(lambda l: l.split('\t'), filter(lambda l: l and not l.startswith('#'), table.split('\n'))))
    header = lines[0]
    data = lines[1:]
    hd = dict((b, a) for a, b in enumerate(header))
    h = lambda l, name: l[hd[name]]
    from itertools import groupby

    gen_varint = [(h(l, 'name'), h(l, 'varint')) for l in data if h(l, 'varint') not in ('1', '??') and h(l, 'vendor').upper() not in ('MS', 'SYB')]
    ms_varint = [(h(l, 'name'), h(l, 'varint')) for l in data if h(l, 'varint') not in ('1', '??') and h(l, 'vendor').upper() == 'MS']
    syb_varint = [(h(l, 'name'), h(l, 'varint')) for l in data if h(l, 'varint') not in ('1', '??') and h(l, 'vendor').upper() == 'SYB']
    types_sizes = [(h(l, 'name'), h(l, 'size')) for l in data]
    fmt = '''\
def tds_get_varint_size(tds, datatype):
{0}
    if IS_TDS7_PLUS(tds):
{1}
    elif IS_TDS50(tds):
{2}
    return 1

def tds_get_size_by_type(servertype):
{3}

def tds_get_conversion_type(srctype, colsize):
    raise Exception('not implemented')
'''
    keyfunc = lambda val: val[1]
    code = fmt.format(
        '\n'.join('    if datatype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(gen_varint, key=keyfunc), keyfunc)),
        '\n'.join('        if datatype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(ms_varint, key=keyfunc), keyfunc)),
        '\n'.join('        if datatype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(syb_varint, key=keyfunc), keyfunc)),
        '\n'.join('    if servertype in ({0},): return {1}'.format(','.join(name for name, _ in g), k) for k, g in groupby(sorted(types_sizes, key=keyfunc), keyfunc)),
        )
    return compile(code, 'autogenerated_types', 'exec')

exec(gen_get_varint_size())


#
# Get column size for wire
#
def tds_fix_column_size(tds, curcol):
    size = curcol.column_size

    if not size:
        size = curcol.column_size
        if is_unicode_type(curcol.column_type):
            size *= 2

    vs = curcol.column_varint_size
    if vs == 0:
        return size
    elif vs == 1:
        size = max(min(size, 255), 1)
    elif vs == 2:
        if curcol.column_type in (XSYBNVARCHAR, XSYBNCHAR):
            mn = 2
        else:
            mn = 1
        size = max(min(size, 8000), mn)
    elif vs == 4:
        if curcol.column_type == SYBNTEXT:
            size = max(min(size, 0x7ffffffe), 2)
        else:
            size = max(min(size, 0x7fffffff), 1)
    return size


def tds_convert_string(tds, char_codec, s):
    if isinstance(s, bytes):
        s = s.decode('utf8')
    return char_codec.encode(s)[0]

_utc = tzutc()


class DatetimeHandler(object):
    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    @classmethod
    def from_python(cls, tds, col, value):
        col.column_type = SYBDATETIMN
        col.size = 8
        Datetime.validate(value)
        return value

    @staticmethod
    def get_declaration(tds, col):
        t = col.column_type
        if t == SYBDATETIME or t == SYBDATETIMN and col.size == 8:
            return "DATETIME"
        elif t == SYBDATETIME4 or t == SYBDATETIMN and col.size == 4:
            return "SMALLDATETIME"

    @staticmethod
    def put_info(tds, col):
        w = tds._writer
        if col.column_type == SYBDATETIMN:
            w.put_byte(col.size)

    @classmethod
    def put_data(cls, tds, col):
        w = tds._writer
        value = col.value
        if col.column_type == SYBDATETIMN:
            if value is None:
                w.put_byte(0)
                return
            else:
                w.put_byte(col.size)

        if col.column_type == SYBDATETIME or col.column_type == SYBDATETIMN and col.size == 8:
            w.write(Datetime.encode(value))
        elif col.column_type == SYBDATETIME4 or col.column_type == SYBDATETIMN and col.size == 4:
            raise NotImplementedError
        else:
            assert False


#
# Fetch character data the wire.
# Output is NOT null terminated.
# If \a char_conv is not NULL, convert data accordingly.
# \param tds         state information for the socket and the TDS protocol
# \param wire_size   size to read from wire (in bytes)
# \param curcol      column information
# \return TDS_SUCCESS or TDS_FAIL (probably memory error on text data)
# \todo put a TDSICONV structure in every TDSCOLUMN
#
def tds_get_char_data(tds, wire_size, curcol):
    r = tds._reader
    #
    # dest is usually a column buffer, allocated when the column's metadata are processed
    # and reused for each row.
    # For blobs, dest is blob->textvalue, and can be reallocated or freed
    # TODO: reallocate if blob and no space
    #
    # silly case, empty string
    if wire_size == 0:
        return ''

    if curcol.char_codec:
        #
        # TODO The conversion should be selected from curcol and tds version
        # TDS7.1/single -> use curcol collation
        # TDS7/single -> use server single byte
        # TDS7+/unicode -> use server (always unicode)
        # TDS5/4.2 -> use server
        # TDS5/UTF-8 -> use server
        # TDS5/UTF-16 -> use UTF-16
        #
        return curcol.char_codec.decode(readall(r, wire_size))[0]
    else:
        return readall(r, wire_size)


class Datetime:
    base_date = datetime(1900, 1, 1)
    min = datetime(1753, 1, 1, 0, 0, 0)
    max = datetime(9999, 12, 31, 23, 59, 59, 997000)
    size = 8

    @classmethod
    def validate(cls, value):
        if not (cls.min <= value <= cls.max):
            raise DataError('Date is out of range')

    @classmethod
    def encode(cls, value):
        cls.validate(value)
        if type(value) == date:
            value = datetime.combine(value, time(0, 0, 0))
        days = (value - cls.base_date).days
        ms = value.microsecond // 1000
        tm = (value.hour * 60 * 60 + value.minute * 60 + value.second) * 300 + int(round(ms * 3 / 10.0))
        return TDS_DATETIME.pack(days, tm)

    @classmethod
    def decode(cls, days, time):
        ms = int(round(time % 300 * 10 / 3.0))
        secs = time // 300
        return cls.base_date + timedelta(days=days, seconds=secs, milliseconds=ms)
