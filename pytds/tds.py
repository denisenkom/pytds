import struct
import logging
import socket
import errno
import os
import select
import sys
import six
from datetime import datetime, date, time, timedelta
from decimal import Decimal, localcontext
from dateutil.tz import tzoffset, tzutc, tzlocal
import uuid
import six
import struct
import sys
from six.moves import map, reduce
from six.moves import xrange
from .collate import *
from .tdsproto import *

logger = logging.getLogger()

ENCRYPTION_ENABLED = False

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


def tds7_crypt_pass(password):
    encoded = bytearray(ucs2_codec.encode(password)[0])
    for i, ch in enumerate(encoded):
        encoded[i] = ((ch << 4) & 0xff | (ch >> 4)) ^ 0xA5
    return encoded


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

_header = struct.Struct('>BBHHBx')
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
    def session(self):
        return self._session

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
        self._type, self._status, self._size, self._session._spid, _ = _header.unpack(header)
        self._have = _header.size
        assert self._size > self._have, 'Empty packet doesn make any sense'
        self._buf = self._transport.read(self._size - self._have)
        self._have += len(self._buf)

    def read_whole_packet(self):
        self._read_packet()
        return readall(self, self._size - _header.size)


class _TdsWriter(object):
    def __init__(self, session, bufsize, little_endian):
        self._session = session
        self._tds = session
        self._transport = session
        self._pos = 0
        self._buf = bytearray(bufsize)
        self._little_endian = little_endian
        self._packet_no = 0

    @property
    def session(self):
        return self._session

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
        return self._little_endian

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
        _header.pack_into(self._buf, 0, self._type, status, self._pos, 0, self._packet_no)
        self._packet_no = (self._packet_no + 1) % 256
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


class BaseType(object):
    def get_typeid(self):
        return self.type


class Bit(BaseType):
    type = SYBBIT

    def get_declaration(self):
        return 'BIT'

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def write_info(self, w):
        w.put_byte(1)

    def write(self, w, value):
        w.put_byte(1 if value else 0)

    def read(self, r):
        return bool(r.get_byte())
Bit.instance = Bit()


class BitN(BaseType):
    type = SYBBITN

    def get_declaration(self):
        return 'BIT'

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size != 1:
            raise InterfaceError('Invalid BIT field size', size)
        return cls()

    def write_info(self, w):
        w.put_byte(1)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            w.put_byte(1)
            w.put_byte(1 if value else 0)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size != 1:
            raise InterfaceError('Invalid BIT field size', size)
        return bool(r.get_byte())


class TinyInt(BaseType):
    type = SYBINT1

    @classmethod
    def from_stream(cls, r):
        return cls()

    def get_declaration(self):
        return 'TINYINT'

    def write_info(self, w):
        pass

    def write(self, w, val):
        w.put_byte(val)

    def read(self, r):
        return r.get_byte()
TinyInt.instance = TinyInt()


class SmallInt(BaseType):
    type = SYBINT2

    @classmethod
    def from_stream(cls, r):
        return cls()

    def get_declaration(self):
        return 'SMALLINT'

    def write_info(self, w):
        pass

    def write(self, w, val):
        w.put_smallint(val)

    def read(self, r):
        return r.get_smallint()
SmallInt.instance = SmallInt()


class Int(BaseType):
    type = SYBINT4

    @classmethod
    def from_stream(cls, r):
        return cls()

    def get_declaration(self):
        return 'INT'

    def write_info(self, w):
        pass

    def write(self, w, val):
        w.put_int(val)

    def read(self, r):
        return r.get_int()
Int.instance = Int()


class BigInt(BaseType):
    type = SYBINT8

    @classmethod
    def from_stream(cls, r):
        return cls()

    def get_declaration(self):
        return 'BIGINT'

    def write_info(self, w):
        pass

    def write(self, w, val):
        w.put_int8(val)

    def read(self, r):
        return r.get_int8()
BigInt.instance = BigInt()


class IntN(BaseType):
    type = SYBINTN

    _declarations = {
        1: 'TINYINT',
        2: 'SMALLINT',
        4: 'INT',
        8: 'BIGINT',
        }

    _struct = {
        1: struct.Struct('b'),
        2: struct.Struct('<h'),
        4: struct.Struct('<l'),
        8: struct.Struct('<q'),
        }

    _subtype = {
        1: TinyInt.instance,
        2: SmallInt.instance,
        4: Int.instance,
        8: BigInt.instance,
        }

    _valid_sizes = {1, 2, 4, 8}

    def __init__(self, size):
        assert size in self._valid_sizes
        self._size = size
        self._current_struct = self._struct[size]
        self._typeid = self._subtype[size].type

    def get_typeid(self):
        return self._typeid

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size not in cls._valid_sizes:
            raise InterfaceError('Invalid size of INTN field', size)
        return cls(size)

    def get_declaration(self):
        return self._declarations[self._size]

    def write_info(self, w):
        w.put_byte(self._size)

    def write(self, w, val):
        if val is None:
            w.put_byte(0)
        else:
            w.put_byte(self._size)
            w.pack(self._current_struct, val)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size not in self._valid_sizes:
            raise InterfaceError('Invalid size of INTN field', size)
        return r.unpack(self._struct[size])[0]


class Real(BaseType):
    type = SYBREAL

    def get_declaration(self):
        return 'REAL'

    def write_info(self, w):
        pass

    def write(self, w, val):
        w.pack(_flt4_struct, val)

    def read(self, r):
        return r.unpack(_flt4_struct)[0]
Real.instance = Real()


class Float(BaseType):
    type = SYBFLT8

    def get_declaration(self):
        return 'FLOAT'

    def write_info(self, w):
        pass

    def write(self, w, val):
        w.pack(_SYBFLT8_STRUCT, val)

    def read(self, r):
        return r.unpack(_SYBFLT8_STRUCT)[0]
Float.instance = Float()


class FloatN(BaseType):
    type = SYBFLTN

    _subtype = {
        4: Real.instance,
        8: Float.instance,
        }

    def __init__(self, size):
        self._size = size
        self._typeid = self._subtype[size].type

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size not in (4, 8):
            raise InterfaceError('Invalid SYBFLTN size', size)
        return cls(size)

    def get_declaration(self):
        if self._size == 8:
            return 'FLOAT'
        else:
            return 'REAL'

    def write_info(self, w):
        w.put_byte(self._size)

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
            if size == 8:
                return r.unpack(_SYBFLT8_STRUCT)[0]
            elif size == 4:
                return r.unpack(_SYBFLT4_STRUCT)[0]
            else:
                raise InterfaceError('Invalid SYBFLTN size', size)


class VarChar70(BaseType):
    type = XSYBVARCHAR

    def __init__(self, size):
        if size <= 0 or size > 8000:
            raise DataError('Invalid size for VARCHAR field')
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        return cls(size)

    def get_declaration(self):
        return 'VARCHAR({})'.format(self._size)

    def write_info(self, w):
        w.put_smallint(self._size)
        #w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_smallint(-1)
        else:
            #if isinstance(val, bytes):
            #    val = val.decode('utf8')
            #w.put_smallint(len(val) * 2)
            #w.put_smallint(len(val))
            #w.write_ucs2(val)
            raise NotImplementedError

    def read(self, r):
        size = r.get_smallint()
        if size < 0:
            return None
        return r.read_str(size, self._codec)


class VarChar71(VarChar70):
    type = XSYBVARCHAR

    def __init__(self, size, collation):
        super(VarChar71, self).__init__(size)
        self._collation = collation
        self._codec = collation.get_codec()

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        collation = r.get_collation()
        return cls(size, collation)

    def write_info(self, w):
        super(VarChar71, self).write_info(w)
        w.put_collation(self._collation)


class VarChar72(VarChar71):
    type = XSYBVARCHAR

    def __init__(self, size, collation):
        self._collation = collation
        self._codec = collation.get_codec()
        self._size = size
        if size == -1:
            self.read = self._read_max
            self.write = self._write_max

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        collation = r.get_collation()
        return cls(size, collation)

    def get_declaration(self):
        if self._size == -1:
            return 'VARCHAR(MAX)'
        else:
            super(VarChar72, self).get_declaration()

    def _write_max(self, w, val):
        if val is None:
            w.put_int8(-1)
        else:
            if isinstance(val, bytes):
                val = val.decode('utf8')
            w.put_int8(len(val) * 2)
            w.put_int(len(val) * 2)
            w.write_ucs2(val)
            w.put_int(0)

    def _read_max(self, r):
        size = r.get_int8()
        if size == -1:
            return None
        chunks = []
        decoder = self._codec.incrementaldecoder()
        while True:
            chunk_len = r.get_int()
            if chunk_len <= 0:
                chunks.append(decoder.decode(b'', True))
                return ''.join(chunks)
            left = chunk_len
            while left:
                buf = r.read(left)
                chunk = decoder.decode(buf)
                left -= len(buf)
                chunks.append(chunk)


class NVarChar70(BaseType):
    type = XSYBNVARCHAR

    def __init__(self, size):
        #if size <= 0 or size > 4000:
        #    raise DataError('Invalid size for NVARCHAR field')
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

    def read(self, r):
        size = r.get_smallint()
        if size < 0:
            return None
        return r.read_str(size, ucs2_codec)


class NVarChar71(NVarChar70):
    def __init__(self, size, collation):
        super(NVarChar71, self).__init__(size)
        self._collation = collation

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        collation = r.get_collation()
        return cls(size, collation)

    def write_info(self, w):
        super(NVarChar71, self).write_info(w)
        w.put_collation(self._collation)


class NVarChar72(NVarChar71):
    def __init__(self, size, collation):
        super(NVarChar72, self).__init__(size, collation)
        if size == -1:
            self.read = self._read_max
            self.write = self._write_max
            self.write_info = self._write_info_max

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        collation = r.get_collation()
        return cls(size, collation)

    def get_declaration(self):
        if self._size == -1:
            return 'NVARCHAR(MAX)'
        else:
            return super(NVarChar72, self).get_declaration()

    def _write_info_max(self, w):
        w.put_smallint(-1)
        w.put_collation(self._collation)

    def _write_max(self, w, val):
        if val is None:
            w.put_int8(-1)
        else:
            if isinstance(val, bytes):
                val = val.decode('utf8')
            w.put_int8(len(val) * 2)
            w.put_int(len(val) * 2)
            w.write_ucs2(val)
            w.put_int(0)

    def _read_max(self, r):
        size = r.get_int8()
        if size == -1:
            return None
        chunks = []
        decoder = ucs2_codec.incrementaldecoder()
        while True:
            chunk_len = r.get_int()
            if chunk_len <= 0:
                chunks.append(decoder.decode(b'', True))
                return ''.join(chunks)
            left = chunk_len
            while left:
                buf = r.read(left)
                chunk = decoder.decode(buf)
                left -= len(buf)
                chunks.append(chunk)


class Xml(NVarChar72):
    type = SYBMSXML

    def __init__(self, schema):
        super(Xml, self).__init__(-1, None)
        self._schema = schema

    @classmethod
    def from_stream(cls, r):
        has_schema = r.get_byte()
        schema = {}
        if has_schema:
            schema['dbname'] = r.read_ucs2(r.get_byte())
            schema['owner'] = r.read_ucs2(r.get_byte())
            schema['collection'] = r.read_ucs2(r.get_smallint())
        return cls(schema)


class Text(BaseType):
    type = SYBTEXT

    @classmethod
    def from_stream(cls, r):
        raise NotImplementedError


class Text71(Text):
    def __init__(self, size, table_name, collation):
        self._size = size
        self._collation = collation
        self._codec = collation.get_codec()
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name, collation)

    def write_info(self, w):
        w.put_int(self._size * 2)

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
        else:
            w.put_int(len(val) * 2)
            w.write_ucs2(val)

    def read(self, r):
        size = r.get_byte()
        if size == 16:  # Jeff's hack
            readall(r, 16)  # textptr
            readall(r, 8)  # timestamp
            colsize = r.get_int()
            return r.read_str(colsize, self._codec)
        else:
            return None


class Text72(Text71):
    def __init__(self, size, table_name_parts, collation):
        super(Text72, self).__init__(size, '.'.join(table_name_parts), collation)
        self._table_name_parts = table_name_parts

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        num_parts = r.get_byte()
        parts = []
        for _ in range(num_parts):
            parts.append(r.read_ucs2(r.get_smallint()))
        return cls(size, parts, collation)


class NText(BaseType):
    type = SYBNTEXT

    @classmethod
    def from_stream(cls, r):
        raise NotImplementedError


class NText71(NText):
    def __init__(self, size, table_name, collation):
        self._size = size
        self._collation = collation
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name, collation)

    def write_info(self, w):
        w.put_int(self._size * 2)

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
        else:
            w.put_int(len(val) * 2)
            w.write_ucs2(val)

    def read(self, r):
        size = r.get_byte()
        if size == 16:  # Jeff's hack
            readall(r, 16)  # textptr
            readall(r, 8)  # timestamp
            colsize = r.get_int()
            return r.read_str(colsize, ucs2_codec)
        else:
            return None


class NText72(NText71):
    def __init__(self, size, table_name_parts, collation):
        self._size = size
        self._collation = collation
        self._table_name_parts = table_name_parts

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        collation = r.get_collation()
        num_parts = r.get_byte()
        parts = []
        for _ in range(num_parts):
            parts.append(r.read_ucs2(r.get_smallint()))
        return cls(size, parts, collation)


class VarBinary(BaseType):
    type = XSYBVARBINARY

    def __init__(self, size):
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        return cls(size)

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

    def read(self, r):
        return readall(r, r.get_smallint())


class VarBinary72(VarBinary):
    def __init__(self, size):
        self._size = size
        if size == -1:
            self.read = self._read_max
            self.write = self._write_max
            self.write_info = self._write_info_max
            self.get_declaration = self._get_declaration_max

    def _get_declaration_max(self):
        return 'VARBINARY(MAX)'

    def _write_info_max(self, w):
        w.put_smallint(-1)

    def _write_max(self, w, val):
        if val is None:
            w.put_int8(-1)
        else:
            w.put_int8(len(val))
            w.put_int(len(val))
            w.write(val)
            w.put_int(0)

    def _read_max(self, r):
        size = r.get_int8()
        if size == -1:
            return None
        chunks = []
        while True:
            chunk_len = r.get_int()
            if chunk_len <= 0:
                return b''.join(chunks)
            left = chunk_len
            while left:
                chunk = r.read(left)
                left -= len(chunk)
                chunks.append(chunk)


class Image(BaseType):
    def __init__(self, size, table_name):
        self._table_name = table_name
        self._size = size

    def get_declaration(self):
        return 'IMAGE'

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name)

    def read(self, r):
        size = r.get_byte()
        if size == 16:  # Jeff's hack
            readall(r, 16)  # textptr
            readall(r, 8)  # timestamp
            colsize = r.get_int()
            return readall(r, colsize)
        else:
            return None


class Image72(Image):
    type = SYBIMAGE

    def __init__(self, size, parts):
        self._parts = parts
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        num_parts = r.get_byte()
        parts = []
        for _ in range(num_parts):
            parts.append(r.read_ucs2(r.get_smallint()))
        return Image72(size, parts)


class BaseDateTime(BaseType):
    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)


class SmallDateTime(BaseDateTime):
    type = SYBDATETIME4

    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    @classmethod
    def from_stream(cls, r):
        return cls()

    def get_declaration(self):
        return 'SMALLDATETIME'

    def write_info(self, w):
        w.put_byte(4)

    def write(self, w, val):
        w.write(Datetime.encode(value))

    def read(self, r):
        days, minutes = r.unpack(TDS_DATETIME4)
        return (self._base_date + timedelta(days=days, minutes=minutes)).replace(tzinfo=r.session.use_tz)
SmallDateTime.instance = SmallDateTime()


class DateTime(BaseDateTime):
    type = SYBDATETIME

    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    @classmethod
    def from_stream(cls, r):
        return cls()

    def get_declaration(self):
        return 'DATETIME'

    def write_info(self, w):
        w.put_byte(8)

    def write(self, w, val):
        w.write(self.encode(value))

    def read(self, r):
        days, time = r.unpack(TDS_DATETIME)
        return _applytz(self.decode(days, time), r.session.use_tz)

    @classmethod
    def validate(cls, value):
        if not (cls._min_date <= value <= cls._max_date):
            raise DataError('Date is out of range')

    @classmethod
    def encode(cls, value):
        cls.validate(value)
        if type(value) == date:
            value = datetime.combine(value, time(0, 0, 0))
        days = (value - cls._base_date).days
        ms = value.microsecond // 1000
        tm = (value.hour * 60 * 60 + value.minute * 60 + value.second) * 300 + int(round(ms * 3 / 10.0))
        return TDS_DATETIME.pack(days, tm)

    @classmethod
    def decode(cls, days, time):
        ms = int(round(time % 300 * 10 / 3.0))
        secs = time // 300
        return cls._base_date + timedelta(days=days, seconds=secs, milliseconds=ms)
DateTime.instance = DateTime()


class DateTimeN(BaseType):
    type = SYBDATETIMN

    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    def __init__(self, size):
        assert size in (4, 8)
        self._size = size

    @classmethod
    def from_stream(self, r):
        size = r.get_byte()
        if size not in (4, 8):
            raise InterfaceError('Invalid SYBDATETIMN size', size)
        return DateTimeN(size)

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
            w.write(DateTime.encode(value))

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size == 4:
            days, minutes = r.unpack(TDS_DATETIME4)
            return (self._base_date + timedelta(days=days, minutes=minutes)).replace(tzinfo=r.session.use_tz)
        elif size == 8:
            days, time = r.unpack(TDS_DATETIME)
            return _applytz(DateTime.decode(days, time), r.session.use_tz)
        else:
            raise InterfaceError('Invalid datetimn size')


class BaseDateTime73(BaseType):
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

    @classmethod
    def from_stream(cls, r):
        return cls()

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

    def read_fixed(self, r):
        return self._read_date(r)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self._read_date(r)
MsDate.instance = MsDate()


class MsTime(BaseDateTime73):
    type = SYBMSTIME

    def __init__(self, prec):
        self._prec = prec
        self._size = self._precision_to_len[prec]

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    def get_declaration(self):
        return 'TIME({})'.format(self._prec)

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            if value.tzinfo:
                if not w.session.use_tz:
                    raise DataError('Timezone-aware datetime is used without specifying use_tz')
                value = value.astimezone(w.session.use_tz).replace(tzinfo=None)
            w.put_byte(self._size)
            self._write_time(w, value, self._prec)

    def read_fixed(self, r, size):
        return self._read_time(r, size, self._prec, r.session.use_tz)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


class DateTime2(BaseDateTime73):
    type = SYBMSDATETIME2

    def __init__(self, prec):
        self._prec = prec
        self._size = self._precision_to_len[prec] + 3

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    def get_declaration(self):
        return 'DATETIME2({})'.format(self._prec)

    def write_info(self, w):
        w.put_byte(self._prec)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
        else:
            if value.tzinfo:
                if not w.session.use_tz:
                    raise DataError('Timezone-aware datetime is used without specifying use_tz')
                value = value.astimezone(w.session.use_tz).replace(tzinfo=None)
            w.put_byte(self._size)
            self._write_time(w, value, self._prec)
            self._write_date(w, value)

    def read_fixed(self, r, size):
        time = self._read_time(r, size - 3, self._prec, r.session.use_tz)
        date = self._read_date(r)
        return datetime.combine(date, time)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


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

    def read_fixed(self, r, size):
        time = self._read_time(r, size - 5, self._prec, _utc)
        date = self._read_date(r)
        tz = tzoffset('', r.get_smallint() * 60)
        return datetime.combine(date, time).astimezone(tz)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


class MsDecimal(BaseType):
    type = SYBDECIMAL

    _max_size = 17

    _bytes_per_prec = [
        #
        # precision can't be 0 but using a value > 0 assure no
        # core if for some bug it's 0...
        #
        1,
        5, 5, 5, 5, 5, 5, 5, 5, 5,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        13, 13, 13, 13, 13, 13, 13, 13, 13,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
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

    def read_fixed(self, r, size):
        positive = r.get_byte()
        buf = readall(r, size - 1)
        return self._decode(positive, buf)

    def read(self, r):
        size = r.get_byte()
        if size <= 0:
            return None
        return self.read_fixed(r, size)


class Money4(BaseType):
    type = SYBMONEY4

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def read(self, r):
        return Decimal(r.get_int()) / 10000
Money4.instance = Money4()


class Money8(BaseType):
    type = SYBMONEY
    _struct = struct.Struct('<lL')

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def get_typeid(self):
        return self.type

    def read(self, r):
        hi, lo = r.unpack(self._struct)
        val = hi * (2 ** 32) + lo
        return Decimal(val) / 10000
Money8.instance = Money8()


class MoneyN(BaseType):
    type = SYBMONEYN
    _subtypes = {
        4: Money4(),
        8: Money8(),
        }

    def __init__(self, size):
        self._size = size
        self._typeid = self._subtypes[size].type

    def get_typeid(self):
        return self._typeid

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size not in (4, 8):
            raise InterfaceError('Invalid SYBMONEYN size', size)
        return cls(size)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size not in (4, 8):
            raise InterfaceError('Invalid SYBMONEYN size', size)
        return self._subtypes[size].read(r)



class MsUnique(BaseType):
    type = SYBUNIQUE

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size != 16:
            raise InterfaceError('Invalid size of UNIQUEIDENTIFIER field')
        return cls.instance

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

    def read_fixed(self, r, size):
        return uuid.UUID(bytes_le=readall(r, size))

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size != 16:
            raise InterfaceError('Invalid size of UNIQUEIDENTIFIER field')
        return self.read_fixed(r, size)
MsUnique.instance = MsUnique()


def _variant_read_str(r, size):
    collation = r.get_collation()
    r.get_usmallint()
    return r.read_str(size, collation.get_codec())


def _variant_read_nstr(r, size):
    r.get_collation()
    r.get_usmallint()
    return r.read_str(size, ucs2_codec)


def _variant_read_decimal(r, size):
    prec, scale = r.unpack(Variant._decimal_info_struct)
    return MsDecimal(prec=prec, scale=scale).read_fixed(r, size)


def _variant_read_binary(r, size):
    r.get_usmallint()
    return readall(r, size)


class Variant(BaseType):
    type = SYBVARIANT

    _decimal_info_struct = struct.Struct('BB')

    _type_map = {
        GUIDTYPE: lambda r, size: MsUnique.instance.read_fixed(r, size),
        BITTYPE: lambda r, size: Bit.instance.read(r),
        INT1TYPE: lambda r, size: TinyInt.instance.read(r),
        INT2TYPE: lambda r, size: SmallInt.instance.read(r),
        INT4TYPE: lambda r, size: Int.instance.read(r),
        INT8TYPE: lambda r, size: BigInt.instance.read(r),
        DATETIMETYPE: lambda r, size: DateTime.instance.read(r),
        DATETIM4TYPE: lambda r, size: SmallDateTime.instance.read(r),
        FLT4TYPE: lambda r, size: Real.instance.read(r),
        FLT8TYPE: lambda r, size: Float.instance.read(r),
        MONEYTYPE: lambda r, size: Money8.instance.read(r),
        MONEY4TYPE: lambda r, size: Money4.instance.read(r),
        DATENTYPE: lambda r, size: MsDate.instance.read_fixed(r),

        TIMENTYPE: lambda r, size: MsTime(prec=r.get_byte()).read_fixed(r, size),
        DATETIME2NTYPE: lambda r, size: DateTime2(prec=r.get_byte()).read_fixed(r, size),
        DATETIMEOFFSETNTYPE: lambda r, size: DateTimeOffset(prec=r.get_byte()).read_fixed(r, size),

        BIGVARBINTYPE: _variant_read_binary,
        BIGBINARYTYPE: _variant_read_binary,

        NUMERICNTYPE: _variant_read_decimal,
        DECIMALNTYPE: _variant_read_decimal,

        BIGVARCHRTYPE: _variant_read_str,
        BIGCHARTYPE: _variant_read_str,
        NVARCHARTYPE: _variant_read_nstr,
        NCHARTYPE: _variant_read_nstr,

        }

    def __init__(self, size):
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        return Variant(size)

    def read(self, r):
        size = r.get_int()
        if size == 0:
            return None

        type_id = r.get_byte()
        prop_bytes = r.get_byte()
        type_factory = self._type_map.get(type_id)
        if not type_factory:
            r.bad_stream('Variant type invalid', type_id)
        return type_factory(r, size - prop_bytes - 2)


_type_map = {
    SYBINT1: TinyInt,
    SYBINT2: SmallInt,
    SYBINT4: Int,
    SYBINT8: BigInt,
    SYBINTN: IntN,
    SYBBIT: Bit,
    SYBBITN: BitN,
    SYBREAL: Real,
    SYBFLT8: Float,
    SYBFLTN: FloatN,
    SYBMONEY4: Money4,
    SYBMONEY: Money8,
    SYBMONEYN: MoneyN,
    XSYBCHAR: VarChar70,
    XSYBVARCHAR: VarChar70,
    XSYBNCHAR: NVarChar70,
    XSYBNVARCHAR: NVarChar70,
    SYBTEXT: Text,
    SYBNTEXT: NText,
    SYBMSXML: Xml,
    XSYBBINARY: VarBinary,
    XSYBVARBINARY: VarBinary,
    SYBIMAGE: Image,
    SYBNUMERIC: MsDecimal,
    SYBDECIMAL: MsDecimal,
    SYBVARIANT: Variant,
    SYBMSDATE: MsDate,
    SYBMSTIME: MsTime,
    SYBMSDATETIME2: DateTime2,
    SYBMSDATETIMEOFFSET: DateTimeOffset,
    SYBDATETIME4: SmallDateTime,
    SYBDATETIME: DateTime,
    SYBDATETIMN: DateTimeN,
    SYBUNIQUE: MsUnique,
    }

_type_map71 = _type_map.copy()
_type_map71.update({
    XSYBCHAR: VarChar71,
    XSYBNCHAR: NVarChar71,
    XSYBVARCHAR: VarChar71,
    XSYBNVARCHAR: NVarChar71,
    SYBTEXT: Text71,
    SYBNTEXT: NText71,
    })

_type_map72 = _type_map.copy()
_type_map72.update({
    XSYBCHAR: VarChar72,
    XSYBNCHAR: NVarChar72,
    XSYBVARCHAR: VarChar72,
    XSYBNVARCHAR: NVarChar72,
    SYBTEXT: Text72,
    SYBNTEXT: NText72,
    XSYBBINARY: VarBinary72,
    XSYBVARBINARY: VarBinary72,
    SYBIMAGE: Image72,
    })


if sys.version_info[0] >= 3:
    def _ord(val):
        return val
else:
    def _ord(val):
        return ord(val)


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
        self._writer = _TdsWriter(self, tds._bufsize, tds.emul_little_endian)
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

    def get_type_factory(self, type_id):
        factory = self._tds._type_map.get(type_id)
        if not factory:
            raise InterfaceError('Invalid type id', type_id)
        return factory

    def get_type_info(self, curcol):
        r = self._reader
        # User defined data type of the column
        curcol.column_usertype = r.get_uint() if IS_TDS72_PLUS(self) else r.get_usmallint()
        curcol.column_flags = r.get_usmallint()  # Flags
        curcol.column_nullable = curcol.column_flags & 0x01
        curcol.column_writeable = (curcol.column_flags & 0x08) > 0
        curcol.column_identity = (curcol.column_flags & 0x10) > 0
        type_id = r.get_byte()
        curcol.type = self.get_type_factory(type_id).from_stream(r)

    def tds7_process_result(self):
        r = self._reader
        #logger.debug("processing TDS7 result metadata.")

        # read number of columns and allocate the columns structure

        num_cols = r.get_smallint()

        # This can be a DUMMY results token from a cursor fetch

        if num_cols == -1:
            #logger.debug("no meta data")
            return TDS_SUCCESS

        self.res_info = None
        self.param_info = None
        self.has_status = False
        self.ret_status = False
        self.current_results = None
        self.rows_affected = TDS_NO_COUNT

        self.current_results = info = _Results()
        if self.cur_cursor:
            self.cur_cursor.res_info = info
            #logger.debug("set current_results to cursor->res_info")
        else:
            self.res_info = info
            #logger.debug("set current_results ({0} column{1}) to tds->res_info".format(num_cols, ('' if num_cols == 1 else "s")))

        #
        # loop through the columns populating COLINFO struct from
        # server response
        #
        #logger.debug("setting up {0} columns".format(num_cols))
        header_tuple = []
        for col in range(num_cols):
            curcol = _Column()
            info.columns.append(curcol)
            self.get_type_info(curcol)

            #
            # under 7.0 lengths are number of characters not
            # number of bytes... read_ucs2 handles this
            #
            curcol.column_name = r.read_ucs2(r.get_byte())
            precision = curcol.type.precision if hasattr(curcol.type, 'precision') else None
            scale = curcol.type.scale if hasattr(curcol.type, 'scale') else None
            header_tuple.append((curcol.column_name, curcol.type.get_typeid(), None, None, precision, scale, curcol.column_nullable))
        info.description = tuple(header_tuple)
        return info

    def process_param_result_tokens(self):
        r = self._reader
        while True:
            token = r.get_byte()
            if token == TDS_PARAM_TOKEN:
                ordinal = r.get_usmallint()
                name = r.read_ucs2(r.get_byte())
                r.get_byte()  # 1 - OUTPUT of sp, 2 - result of udf
                param = _Column()
                param.column_name = name
                self.get_type_info(param)
                param.value = param.type.read(r)
                self.output_params[ordinal] = param
            else:
                r.unget_byte()
                return

    def process_cancel(self):
        '''
        Process the incoming token stream until it finds
        an end token (DONE, DONEPROC, DONEINPROC) with the cancel flag set.
        At that point the connection should be ready to handle a new query.
        '''
        from .token import tds_process_tokens
        # silly cases, nothing to do
        if not self.in_cancel:
            return TDS_SUCCESS
        # TODO handle cancellation sending data
        if self.state != TDS_PENDING:
            return TDS_SUCCESS

        # TODO support TDS5 cancel, wait for cancel packet first, then wait for done
        while True:
            rc, result_type, _ = tds_process_tokens(self, 0)

            if rc == TDS_FAIL:
                raise Exception('TDS_FAIL')
            elif rc in (TDS_CANCELLED, TDS_SUCCESS, TDS_NO_MORE_RESULTS):
                return TDS_SUCCESS

    def process_msg(self, marker):
        r = self._reader
        r.get_smallint()  # size
        msg = {}
        msg['marker'] = marker
        msg['msgno'] = r.get_int()
        msg['state'] = r.get_byte()
        msg['severity'] = r.get_byte()
        msg['sql_state'] = None
        has_eed = False
        if marker == TDS_EED_TOKEN:
            if msg['severity'] <= 10:
                msg['priv_msg_type'] = 0
            else:
                msg['priv_msg_type'] = 1
            len_sqlstate = r.get_byte()
            msg['sql_state'] = readall(r, len_sqlstate)
            has_eed = r.get_byte()
            # junk status and transaction state
            r.get_smallint()
        elif marker == TDS_INFO_TOKEN:
            msg['priv_msg_type'] = 0
        elif marker == TDS_ERROR_TOKEN:
            msg['priv_msg_type'] = 1
        else:
            logger.error('tds_process_msg() called with unknown marker "{0}"'.format(marker))
        #logger.debug('tds_process_msg() reading message {0} from server'.format(msg['msgno']))
        msg['message'] = r.read_ucs2(r.get_smallint())
        # server name
        msg['server'] = r.read_ucs2(r.get_byte())
        if not msg['server'] and self.login:
            msg['server'] = self.server_name
        # stored proc name if available
        msg['proc_name'] = r.read_ucs2(r.get_byte())
        msg['line_number'] = r.get_int() if IS_TDS72_PLUS(self) else r.get_smallint()
        if not msg['sql_state']:
            #msg['sql_state'] = tds_alloc_lookup_sqlstate(self, msg['msgno'])
            pass
        # in case extended error data is sent, we just try to discard it
        if has_eed:
            while True:
                next_marker = r.get_byte()
                if next_marker in (TDS5_PARAMFMT_TOKEN, TDS5_PARAMFMT2_TOKEN, TDS5_PARAMS_TOKEN):
                    tds_process_default_tokens(self, next_marker)
                else:
                    break
            r.unget_byte()

        # call msg_handler

        # special case
        if marker == TDS_EED_TOKEN and self.cur_dyn and self.is_mssql() and msg['msgno'] == 2782:
            self.cur_dyn.emulated = 1
        elif marker == TDS_INFO_TOKEN and msg['msgno'] == 16954 and \
                self.is_mssql() and self.internal_sp_called == TDS_SP_CURSOROPEN and\
                self.cur_cursor:
                    # here mssql say "Executing SQL directly; no cursor." opening cursor
                        pass
        else:
            # EED can be followed to PARAMFMT/PARAMS, do not store it in dynamic
            self.cur_dyn = None
        self.messages.append(msg)

    def process_row(self):
        r = self._reader
        info = self.current_results
        #if not info:
        #    raise Exception('TDS_FAIL')

        #assert len(info.columns) > 0

        info.row_count += 1
        for curcol in info.columns:
            #logger.debug("process_row(): reading column %d" % i)
            curcol.value = curcol.type.read(r)
        return TDS_SUCCESS

    # NBC=null bitmap compression row
    # http://msdn.microsoft.com/en-us/library/dd304783(v=prot.20).aspx
    def process_nbcrow(self):
        r = self._reader
        info = self.current_results
        if not info:
            raise Exception('TDS_FAIL')
        assert len(info.columns) > 0
        info.row_count += 1

        # reading bitarray for nulls, 1 represent null values for
        # corresponding fields
        nbc = readall(r, (len(info.columns) + 7) // 8)
        for i, curcol in enumerate(info.columns):
            if _ord(nbc[i // 8]) & (1 << (i % 8)):
                curcol.value = None
            else:
                curcol.value = curcol.type.read(r)
        return TDS_SUCCESS

    def process_end(self, marker):
        r = self._reader
        status = r.get_usmallint()
        r.get_usmallint()  # cur_cmd
        more_results = status & TDS_DONE_MORE_RESULTS != 0
        was_cancelled = status & TDS_DONE_CANCELLED != 0
        error = status & TDS_DONE_ERROR != 0
        done_count_valid = status & TDS_DONE_COUNT != 0
        #logger.debug(
        #    'process_end: more_results = {0}\n'
        #    '\t\twas_cancelled = {1}\n'
        #    '\t\terror = {2}\n'
        #    '\t\tdone_count_valid = {3}'.format(more_results, was_cancelled, error, done_count_valid))
        if self.res_info:
            self.res_info.more_results = more_results
            if not self.current_results:
                self.current_results = self.res_info
        rows_affected = r.get_int8() if IS_TDS72_PLUS(self) else r.get_int()
        #logger.debug('\t\trows_affected = {0}'.format(rows_affected))
        if was_cancelled or (not more_results and not self.in_cancel):
            #logger.debug('process_end() state set to TDS_IDLE')
            self.in_cancel = False
            self.set_state(TDS_IDLE)
        if self.is_dead():
            raise Exception('TDS_FAIL')
        if done_count_valid:
            self.rows_affected = rows_affected
        else:
            self.rows_affected = -1
        return (TDS_CANCELLED if was_cancelled else TDS_SUCCESS), status

    def process_env_chg(self):
        r = self._reader
        size = r.get_smallint()
        type = r.get_byte()
        if type == TDS_ENV_SQLCOLLATION:
            size = r.get_byte()
            #logger.debug("process_env_chg(): {0} bytes of collation data received".format(size))
            #logger.debug("self.collation was {0}".format(self.conn.collation))
            self.conn.collation = r.get_collation()
            r.skip(size - 5)
            #tds7_srv_charset_changed(tds, tds.conn.collation)
            #logger.debug("self.collation now {0}".format(self.conn.collation))
            # discard old one
            r.skip(r.get_byte())
        elif type == TDS_ENV_BEGINTRANS:
            size = r.get_byte()
            # TODO: parse transaction
            self.conn.tds72_transaction = r.get_uint8()
            r.skip(r.get_byte())
        elif type == TDS_ENV_COMMITTRANS or type == TDS_ENV_ROLLBACKTRANS:
            self.conn.tds72_transaction = 0
            r.skip(r.get_byte())
            r.skip(r.get_byte())
        elif type == TDS_ENV_PACKSIZE:
            newval = r.read_ucs2(r.get_byte())
            oldval = r.read_ucs2(r.get_byte())
            new_block_size = int(newval)
            if new_block_size >= 512:
                #logger.info("changing block size from {0} to {1}".format(oldval, new_block_size))
                #
                # Is possible to have a shrink if server limits packet
                # size more than what we specified
                #
                # Reallocate buffer if possible (strange values from server or out of memory) use older buffer */
                self._writer.bufsize = new_block_size
        elif type == TDS_ENV_DATABASE:
            newval = r.read_ucs2(r.get_byte())
            oldval = r.read_ucs2(r.get_byte())
            self.conn.env.database = newval
        elif type == TDS_ENV_LANG:
            newval = r.read_ucs2(r.get_byte())
            oldval = r.read_ucs2(r.get_byte())
            self.conn.env.language = newval
        elif type == TDS_ENV_CHARSET:
            newval = r.read_ucs2(r.get_byte())
            oldval = r.read_ucs2(r.get_byte())
            #logger.debug("server indicated charset change to \"{0}\"\n".format(newval))
            self.conn.env.charset = newval
            tds_srv_charset_changed(self, newval)
        elif type == TDS_ENV_DB_MIRRORING_PARTNER:
            newval = r.read_ucs2(r.get_byte())
            oldval = r.read_ucs2(r.get_byte())

        else:
            # discard byte values, not still supported
            # TODO support them
            # discard new one
            r.skip(r.get_byte())
            # discard old one
            r.skip(r.get_byte())

    def process_auth(self):
        r = self._reader
        w = self._writer
        pdu_size = r.get_smallint()
        if not self.authentication:
            raise Error('Got unexpected token')
        packet = self.authentication.handle_next(readall(r, pdu_size))
        if packet:
            w.write(packet)
            w.flush()

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
            column.type = BitN()
        elif isinstance(value, six.integer_types):
            if -2 ** 31 <= value <= 2 ** 31 - 1:
                column.type = IntN(4)
            elif -2 ** 63 <= value <= 2 ** 63 - 1:
                column.type = IntN(8)
            elif -10 ** 38 + 1 <= value <= 10 ** 38 - 1:
                column.type = MsDecimal(0, 38)
            else:
                raise DataError('Numeric value out or range')
        elif isinstance(value, float):
            column.type = FloatN(8)
        elif isinstance(value, Binary):
            size = len(value)
            if size > 8000:
                if IS_TDS72_PLUS(tds):
                    column.type = VarBinary72(-1)
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
                    column.type = NVarChar72(-1, self.conn.collation)
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
                    column.type = DateTime2(6)
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
            column.type = MsTime(6)
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

    VERSION = 0
    ENCRYPTION = 1
    INSTOPT = 2
    THREADID = 3
    MARS = 4
    TRACEID = 5
    TERMINATOR = 0xff

    def tds71_do_login(self, login):
        instance_name = login.instance_name or 'MSSQLServer'
        encryption_level = login.encryption_level
        if IS_TDS72_PLUS(self):
            START_POS = 26
            buf = struct.pack(
                b'>BHHBHHBHHBHHBHHB',
                #netlib version
                self.VERSION, START_POS, 6,
                #encryption
                self.ENCRYPTION, START_POS + 6, 1,
                #instance
                self.INSTOPT, START_POS + 6 + 1, len(instance_name) + 1,
                # thread id
                self.THREADID, START_POS + 6 + 1 + len(instance_name) + 1, 4,
                # MARS enabled
                self.MARS, START_POS + 6 + 1 + len(instance_name) + 1 + 4, 1,
                # end
                self.TERMINATOR
                )
        else:
            START_POS = 21
            buf = struct.pack(
                b'>BHHBHHBHHBHHB',
                #netlib version
                self.VERSION, START_POS, 6,
                #encryption
                self.ENCRYPTION, START_POS + 6, 1,
                #instance
                self.INSTOPT, START_POS + 6 + 1, len(instance_name) + 1,
                # thread id
                self.THREADID, START_POS + 6 + 1 + len(instance_name) + 1, 4,
                # end
                self.TERMINATOR
                )
        assert START_POS == len(buf)
        w = self._writer
        w.begin_packet(TDS71_PRELOGIN)
        w.write(buf)
        from pytds import intversion
        w.put_uint_be(intversion)
        w.put_usmallint_be(0)
        # encryption
        if ENCRYPTION_ENABLED and encryption_supported:
            w.put_byte(1 if encryption_level >= TDS_ENCRYPTION_REQUIRE else 0)
        else:
            if encryption_level >= TDS_ENCRYPTION_REQUIRE:
                raise Error('Client requested encryption but it is not supported')
            # not supported
            w.put_byte(2)
        w.write(instance_name.encode('ascii'))
        w.put_byte(0)  # zero terminate instance_name
        w.put_int(os.getpid())  # TODO: change this to thread id
        if IS_TDS72_PLUS(self):
            # MARS (1 enabled)
            w.put_byte(1 if login.use_mars else 0)
        w.flush()
        p = self._reader.read_whole_packet()
        size = len(p)
        if size <= 0 or self._reader.packet_type != 4:
            raise Error('TDS_FAIL')
        # default 2, no certificate, no encryptption
        crypt_flag = 2
        i = 0
        byte_struct = struct.Struct('B')
        off_len_struct = struct.Struct('>HH')
        prod_version_struct = struct.Struct('>LH')
        while True:
            if i >= size:
                raise Error('TDS_FAIL')
            type, = byte_struct.unpack_from(p, i)
            if type == 0xff:
                break
            if i + 4 > size:
                raise Error('TDS_FAIL')
            off, l = off_len_struct.unpack_from(p, i + 1)
            if off > size or off + l > size:
                raise Error('TDS_FAIL')
            if type == self.VERSION:
                self.conn.product_version = prod_version_struct.unpack_from(p, off)
            elif type == self.ENCRYPTION and l >= 1:
                crypt_flag, = byte_struct.unpack_from(p, off)
            elif type == self.MARS:
                self.conn._mars_enabled = bool(byte_struct.unpack_from(p, off)[0])
            i += 5
        # we readed all packet
        logger.debug('detected flag %d', crypt_flag)
        # if server do not has certificate do normal login
        if crypt_flag == 2:
            if encryption_level >= TDS_ENCRYPTION_REQUIRE:
                raise Error('Server required encryption but it is not supported')
            return self.tds7_send_login(login)
        self._sock = ssl.wrap_socket(self._sock, ssl_version=ssl.PROTOCOL_SSLv3)
        return self.tds7_send_login(login)

    def tds7_send_login(self, login):
        option_flag2 = login.option_flag2
        user_name = login.user_name
        w = self._writer
        w.begin_packet(TDS7_LOGIN)
        self.authentication = None
        if len(login.password) > 128:
            raise Error('Password should be not more than 128 characters')
        current_pos = 86 + 8 if IS_TDS72_PLUS(self) else 86
        client_host_name = socket.gethostname()
        login.client_host_name = client_host_name
        packet_size = current_pos + (len(client_host_name) + len(login.app_name) + len(login.server_name) + len(login.library) + len(login.language) + len(login.database)) * 2
        if login.auth:
            self.authentication = login.auth
            auth_packet = login.auth.create_packet()
            packet_size += len(auth_packet)
        else:
            auth_packet = ''
            packet_size += (len(user_name) + len(login.password)) * 2
        w.put_int(packet_size)
        w.put_uint(login.tds_version)
        w.put_int(w.bufsize)
        from pytds import intversion
        w.put_uint(intversion)
        w.put_int(os.getpid())
        w.put_uint(0)  # connection id
        option_flag1 = TDS_SET_LANG_ON | TDS_USE_DB_NOTIFY | TDS_INIT_DB_FATAL
        if not login.bulk_copy:
            option_flag1 |= TDS_DUMPLOAD_OFF
        w.put_byte(option_flag1)
        if self.authentication:
            option_flag2 |= TDS_INTEGRATED_SECURITY_ON
        w.put_byte(option_flag2)
        type_flags = 0
        if login.readonly:
            type_flags |= (2 << 5)
        w.put_byte(type_flags)
        option_flag3 = TDS_UNKNOWN_COLLATION_HANDLING
        w.put_byte(option_flag3 if IS_TDS73_PLUS(self) else 0)
        mins_fix = tzlocal().utcoffset(datetime.now()).total_seconds() // 60
        w.put_int(mins_fix)
        w.put_int(login.client_lcid)
        w.put_smallint(current_pos)
        w.put_smallint(len(client_host_name))
        current_pos += len(client_host_name) * 2
        if self.authentication:
            w.put_smallint(0)
            w.put_smallint(0)
            w.put_smallint(0)
            w.put_smallint(0)
        else:
            w.put_smallint(current_pos)
            w.put_smallint(len(user_name))
            current_pos += len(user_name) * 2
            w.put_smallint(current_pos)
            w.put_smallint(len(login.password))
            current_pos += len(login.password) * 2
        w.put_smallint(current_pos)
        w.put_smallint(len(login.app_name))
        current_pos += len(login.app_name) * 2
        # server name
        w.put_smallint(current_pos)
        w.put_smallint(len(login.server_name))
        current_pos += len(login.server_name) * 2
        # reserved
        w.put_smallint(0)
        w.put_smallint(0)
        # library name
        w.put_smallint(current_pos)
        w.put_smallint(len(login.library))
        current_pos += len(login.library) * 2
        # language
        w.put_smallint(current_pos)
        w.put_smallint(len(login.language))
        current_pos += len(login.language) * 2
        # database name
        w.put_smallint(current_pos)
        w.put_smallint(len(login.database))
        current_pos += len(login.database) * 2
        # ClientID
        mac_address = struct.pack('>Q', uuid.getnode())[:6]
        w.write(mac_address)
        # authentication
        w.put_smallint(current_pos)
        w.put_smallint(len(auth_packet))
        current_pos += len(auth_packet)
        # db file
        w.put_smallint(current_pos)
        w.put_smallint(len(login.attach_db_file))
        current_pos += len(login.attach_db_file) * 2
        if IS_TDS72_PLUS(self):
            # new password
            w.put_smallint(current_pos)
            w.put_smallint(0)
            # sspi long
            w.put_int(0)
        w.write_ucs2(client_host_name)
        if not self.authentication:
            w.write_ucs2(user_name)
            w.write(tds7_crypt_pass(login.password))
        w.write_ucs2(login.app_name)
        w.write_ucs2(login.server_name)
        w.write_ucs2(login.library)
        w.write_ucs2(login.language)
        w.write_ucs2(login.database)
        if self.authentication:
            w.write(auth_packet)
        w.write_ucs2(login.attach_db_file)
        w.flush()


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
                    if IS_TDS72_PLUS(self):
                        self._type_map = _type_map72
                    elif IS_TDS71_PLUS(self):
                        self._type_map = _type_map71
                    else:
                        self._type_map = _type_map
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


if sys.version_info[0] >= 3:
    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + val, reversed(buf), 0)
else:
    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + ord(val), reversed(buf), 0)


_utc = tzutc()
