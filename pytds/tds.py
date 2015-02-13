import struct
import codecs
from contextlib import contextmanager
import logging
import socket
import sys
from datetime import datetime, date, time, timedelta
from decimal import Decimal, localcontext
from . import tz
import re
import uuid
import six
import types
from six.moves import reduce
from six.moves import xrange
try:
    import ssl
except:
    encryption_supported = False
else:
    encryption_supported = True
from .collate import ucs2_codec, Collation, lcid2charset, raw_collation

logger = logging.getLogger()

ENCRYPTION_ENABLED = False


# tds protocol versions
TDS70 = 0x70000000
TDS71 = 0x71000000
TDS71rev1 = 0x71000001
TDS72 = 0x72090002
TDS73A = 0x730A0003
TDS73 = TDS73A
TDS73B = 0x730B0003
TDS74 = 0x74000004

IS_TDS7_PLUS = lambda x: x.tds_version >= TDS70
IS_TDS71_PLUS = lambda x: x.tds_version >= TDS71
IS_TDS72_PLUS = lambda x: x.tds_version >= TDS72
IS_TDS73_PLUS = lambda x: x.tds_version >= TDS73A

# packet types
TDS_QUERY = 1
TDS_LOGIN = 2
TDS_RPC = 3
TDS_REPLY = 4
TDS_CANCEL = 6
TDS_BULK = 7
TDS7_TRANS = 14  # transaction management
TDS_NORMAL = 15
TDS7_LOGIN = 16
TDS7_AUTH = 17
TDS71_PRELOGIN = 18

# mssql login options flags
# option_flag1_values
TDS_BYTE_ORDER_X86 = 0
TDS_CHARSET_ASCII = 0
TDS_DUMPLOAD_ON = 0
TDS_FLOAT_IEEE_754 = 0
TDS_INIT_DB_WARN = 0
TDS_SET_LANG_OFF = 0
TDS_USE_DB_SILENT = 0
TDS_BYTE_ORDER_68000 = 0x01
TDS_CHARSET_EBDDIC = 0x02
TDS_FLOAT_VAX = 0x04
TDS_FLOAT_ND5000 = 0x08
TDS_DUMPLOAD_OFF = 0x10  # prevent BCP
TDS_USE_DB_NOTIFY = 0x20
TDS_INIT_DB_FATAL = 0x40
TDS_SET_LANG_ON = 0x80

#enum option_flag2_values {
TDS_INIT_LANG_WARN = 0
TDS_INTEGRATED_SECURTY_OFF = 0
TDS_ODBC_OFF = 0
TDS_USER_NORMAL = 0  # SQL Server login
TDS_INIT_LANG_REQUIRED = 0x01
TDS_ODBC_ON = 0x02
TDS_TRANSACTION_BOUNDARY71 = 0x04  # removed in TDS 7.2
TDS_CACHE_CONNECT71 = 0x08  # removed in TDS 7.2
TDS_USER_SERVER = 0x10  # reserved
TDS_USER_REMUSER = 0x20  # DQ login
TDS_USER_SQLREPL = 0x40  # replication login
TDS_INTEGRATED_SECURITY_ON = 0x80

#enum option_flag3_values TDS 7.3+
TDS_RESTRICTED_COLLATION = 0
TDS_CHANGE_PASSWORD = 0x01
TDS_SEND_YUKON_BINARY_XML = 0x02
TDS_REQUEST_USER_INSTANCE = 0x04
TDS_UNKNOWN_COLLATION_HANDLING = 0x08
TDS_ANY_COLLATION = 0x10

TDS5_PARAMFMT2_TOKEN = 32  # 0x20
TDS_LANGUAGE_TOKEN = 33  # 0x20    TDS 5.0 only
TDS_ORDERBY2_TOKEN = 34  # 0x22
TDS_ROWFMT2_TOKEN = 97  # 0x61    TDS 5.0 only
TDS_LOGOUT_TOKEN = 113  # 0x71    TDS 5.0 only?
TDS_RETURNSTATUS_TOKEN = 121  # 0x79
TDS_PROCID_TOKEN = 124  # 0x7C    TDS 4.2 only
TDS7_RESULT_TOKEN = 129  # 0x81    TDS 7.0 only
TDS7_COMPUTE_RESULT_TOKEN = 136  # 0x88    TDS 7.0 only
TDS_COLNAME_TOKEN = 160  # 0xA0    TDS 4.2 only
TDS_COLFMT_TOKEN = 161  # 0xA1    TDS 4.2 only
TDS_DYNAMIC2_TOKEN = 163  # 0xA3
TDS_TABNAME_TOKEN = 164  # 0xA4
TDS_COLINFO_TOKEN = 165  # 0xA5
TDS_OPTIONCMD_TOKEN = 166  # 0xA6
TDS_COMPUTE_NAMES_TOKEN = 167  # 0xA7
TDS_COMPUTE_RESULT_TOKEN = 168  # 0xA8
TDS_ORDERBY_TOKEN = 169  # 0xA9
TDS_ERROR_TOKEN = 170  # 0xAA
TDS_INFO_TOKEN = 171  # 0xAB
TDS_PARAM_TOKEN = 172  # 0xAC
TDS_LOGINACK_TOKEN = 173  # 0xAD
TDS_CONTROL_TOKEN = 174  # 0xAE
TDS_ROW_TOKEN = 209  # 0xD1
TDS_NBC_ROW_TOKEN = 210  # 0xD2    as of TDS 7.3.B
TDS_CMP_ROW_TOKEN = 211  # 0xD3
TDS5_PARAMS_TOKEN = 215  # 0xD7    TDS 5.0 only
TDS_CAPABILITY_TOKEN = 226  # 0xE2
TDS_ENVCHANGE_TOKEN = 227  # 0xE3
TDS_EED_TOKEN = 229  # 0xE5
TDS_DBRPC_TOKEN = 230  # 0xE6
TDS5_DYNAMIC_TOKEN = 231  # 0xE7    TDS 5.0 only
TDS5_PARAMFMT_TOKEN = 236  # 0xEC    TDS 5.0 only
TDS_AUTH_TOKEN = 237  # 0xED    TDS 7.0 only
TDS_RESULT_TOKEN = 238  # 0xEE
TDS_DONE_TOKEN = 253  # 0xFD
TDS_DONEPROC_TOKEN = 254  # 0xFE
TDS_DONEINPROC_TOKEN = 255  # 0xFF

# CURSOR support: TDS 5.0 only
TDS_CURCLOSE_TOKEN = 128  # 0x80    TDS 5.0 only
TDS_CURDELETE_TOKEN = 129  # 0x81    TDS 5.0 only
TDS_CURFETCH_TOKEN = 130  # 0x82    TDS 5.0 only
TDS_CURINFO_TOKEN = 131  # 0x83    TDS 5.0 only
TDS_CUROPEN_TOKEN = 132  # 0x84    TDS 5.0 only
TDS_CURDECLARE_TOKEN = 134  # 0x86    TDS 5.0 only

# environment type field
TDS_ENV_DATABASE = 1
TDS_ENV_LANG = 2
TDS_ENV_CHARSET = 3
TDS_ENV_PACKSIZE = 4
TDS_ENV_LCID = 5
TDS_ENV_SQLCOLLATION = 7
TDS_ENV_BEGINTRANS = 8
TDS_ENV_COMMITTRANS = 9
TDS_ENV_ROLLBACKTRANS = 10
TDS_ENV_ENLIST_DTC_TRANS = 11
TDS_ENV_DEFECT_TRANS = 12
TDS_ENV_DB_MIRRORING_PARTNER = 13
TDS_ENV_PROMOTE_TRANS = 15
TDS_ENV_TRANS_MANAGER_ADDR = 16
TDS_ENV_TRANS_ENDED = 17
TDS_ENV_RESET_COMPLETION_ACK = 18
TDS_ENV_INSTANCE_INFO = 19
TDS_ENV_ROUTING = 20

# Microsoft internal stored procedure id's
TDS_SP_CURSOR = 1
TDS_SP_CURSOROPEN = 2
TDS_SP_CURSORPREPARE = 3
TDS_SP_CURSOREXECUTE = 4
TDS_SP_CURSORPREPEXEC = 5
TDS_SP_CURSORUNPREPARE = 6
TDS_SP_CURSORFETCH = 7
TDS_SP_CURSOROPTION = 8
TDS_SP_CURSORCLOSE = 9
TDS_SP_EXECUTESQL = 10
TDS_SP_PREPARE = 11
TDS_SP_EXECUTE = 12
TDS_SP_PREPEXEC = 13
TDS_SP_PREPEXECRPC = 14
TDS_SP_UNPREPARE = 15

# Flags returned in TDS_DONE token
TDS_DONE_FINAL = 0
TDS_DONE_MORE_RESULTS = 0x01  # more results follow
TDS_DONE_ERROR = 0x02  # error occurred
TDS_DONE_INXACT = 0x04  # transaction in progress
TDS_DONE_PROC = 0x08  # results are from a stored procedure
TDS_DONE_COUNT = 0x10  # count field in packet is valid
TDS_DONE_CANCELLED = 0x20  # acknowledging an attention command (usually a cancel)
TDS_DONE_EVENT = 0x40  # part of an event notification.
TDS_DONE_SRVERROR = 0x100  # SQL server server error


SYBVOID = 31  # 0x1F
IMAGETYPE = SYBIMAGE = 34  # 0x22
TEXTTYPE = SYBTEXT = 35  # 0x23
SYBVARBINARY = 37  # 0x25
INTNTYPE = SYBINTN = 38  # 0x26
SYBVARCHAR = 39         # 0x27
BINARYTYPE = SYBBINARY = 45  # 0x2D
SYBCHAR = 47  # 0x2F
INT1TYPE = SYBINT1 = 48  # 0x30
BITTYPE = SYBBIT = 50  # 0x32
INT2TYPE = SYBINT2 = 52  # 0x34
INT4TYPE = SYBINT4 = 56  # 0x38
DATETIM4TYPE = SYBDATETIME4 = 58  # 0x3A
FLT4TYPE = SYBREAL = 59  # 0x3B
MONEYTYPE = SYBMONEY = 60  # 0x3C
DATETIMETYPE = SYBDATETIME = 61  # 0x3D
FLT8TYPE = SYBFLT8 = 62  # 0x3E
NTEXTTYPE = SYBNTEXT = 99  # 0x63
SYBNVARCHAR = 103  # 0x67
BITNTYPE = SYBBITN = 104  # 0x68
NUMERICNTYPE = SYBNUMERIC = 108  # 0x6C
DECIMALNTYPE = SYBDECIMAL = 106  # 0x6A
FLTNTYPE = SYBFLTN = 109  # 0x6D
MONEYNTYPE = SYBMONEYN = 110  # 0x6E
DATETIMNTYPE = SYBDATETIMN = 111  # 0x6F
MONEY4TYPE = SYBMONEY4 = 122  # 0x7A

INT8TYPE = SYBINT8 = 127  # 0x7F
BIGCHARTYPE = XSYBCHAR = 175  # 0xAF
BIGVARCHRTYPE = XSYBVARCHAR = 167  # 0xA7
NVARCHARTYPE = XSYBNVARCHAR = 231  # 0xE7
NCHARTYPE = XSYBNCHAR = 239  # 0xEF
BIGVARBINTYPE = XSYBVARBINARY = 165  # 0xA5
BIGBINARYTYPE = XSYBBINARY = 173  # 0xAD
GUIDTYPE = SYBUNIQUE = 36  # 0x24
SSVARIANTTYPE = SYBVARIANT = 98  # 0x62
UDTTYPE = SYBMSUDT = 240  # 0xF0
XMLTYPE = SYBMSXML = 241  # 0xF1
DATENTYPE = SYBMSDATE = 40  # 0x28
TIMENTYPE = SYBMSTIME = 41  # 0x29
DATETIME2NTYPE = SYBMSDATETIME2 = 42  # 0x2a
DATETIMEOFFSETNTYPE = SYBMSDATETIMEOFFSET = 43  # 0x2b

#
# Sybase only types
#
SYBLONGBINARY = 225  # 0xE1
SYBUINT1 = 64  # 0x40
SYBUINT2 = 65  # 0x41
SYBUINT4 = 66  # 0x42
SYBUINT8 = 67  # 0x43
SYBBLOB = 36  # 0x24
SYBBOUNDARY = 104  # 0x68
SYBDATE = 49  # 0x31
SYBDATEN = 123  # 0x7B
SYB5INT8 = 191  # 0xBF
SYBINTERVAL = 46  # 0x2E
SYBLONGCHAR = 175  # 0xAF
SYBSENSITIVITY = 103  # 0x67
SYBSINT1 = 176  # 0xB0
SYBTIME = 51  # 0x33
SYBTIMEN = 147  # 0x93
SYBUINTN = 68  # 0x44
SYBUNITEXT = 174  # 0xAE
SYBXML = 163  # 0xA3

TDS_UT_TIMESTAMP = 80

# compute operator
SYBAOPCNT = 0x4b
SYBAOPCNTU = 0x4c
SYBAOPSUM = 0x4d
SYBAOPSUMU = 0x4e
SYBAOPAVG = 0x4f
SYBAOPAVGU = 0x50
SYBAOPMIN = 0x51
SYBAOPMAX = 0x52

# mssql2k compute operator
SYBAOPCNT_BIG = 0x09
SYBAOPSTDEV = 0x30
SYBAOPSTDEVP = 0x31
SYBAOPVAR = 0x32
SYBAOPVARP = 0x33
SYBAOPCHECKSUM_AGG = 0x72

# param flags
fByRefValue = 1
fDefaultValue = 2

TDS_IDLE = 0
TDS_QUERYING = 1
TDS_PENDING = 2
TDS_READING = 3
TDS_DEAD = 4
state_names = ['IDLE', 'QUERYING', 'PENDING', 'READING', 'DEAD']

TDS_ENCRYPTION_OFF = 0
TDS_ENCRYPTION_REQUEST = 1
TDS_ENCRYPTION_REQUIRE = 2

USE_CORK = hasattr(socket, 'TCP_CORK')

TDS_NO_COUNT = -1

_utc = tz.utc

_header = struct.Struct('>BBHHBx')
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
_uint8_le = struct.Struct('<Q')
_uint8_be = struct.Struct('>Q')
_flt8_struct = struct.Struct('d')
_flt4_struct = struct.Struct('f')


PLP_MARKER = 0xffff
PLP_NULL = 0xffffffffffffffff
PLP_UNKNOWN = 0xfffffffffffffffe


class PlpReader(object):
    """ Partially length prefixed reader

    Spec: http://msdn.microsoft.com/en-us/library/dd340469.aspx
    """
    def __init__(self, r):
        """
        :param r: An instance of :class:`_TdsReader`
        """
        self._rdr = r
        size = r.get_uint8()
        self._size = size

    def is_null(self):
        """
        :return: True if stored value is NULL
        """
        return self._size == PLP_NULL

    def is_unknown_len(self):
        """
        :return: True if total size is unknown upfront
        """
        return self._size == PLP_UNKNOWN

    def size(self):
        """
        :return: Total size in bytes if is_uknown_len and is_null are both False
        """
        return self._size

    def chunks(self):
        """ Generates chunks from stream, each chunk is an instace of bytes.
        """
        if self.is_null():
            return
        total = 0
        while True:
            chunk_len = self._rdr.get_uint()
            if chunk_len == 0:
                if not self.is_unknown_len() and total != self._size:
                    msg = "PLP actual length (%d) doesn't match reported length (%d)" % (total, self._size)
                    self._rdr.session.bad_stream(msg)

                return

            total += chunk_len
            left = chunk_len
            while left:
                buf = self._rdr.read(left)
                yield buf
                left -= len(buf)


def iterdecode(iterable, codec):
    """ Uses an incremental decoder to decode each chunk in iterable.
    This function is a generator.

    :param codec: An instance of codec
    """
    decoder = codec.incrementaldecoder()
    for chunk in iterable:
        yield decoder.decode(chunk)
    yield decoder.decode(b'', True)


class SimpleLoadBalancer(object):
    def __init__(self, hosts):
        self._hosts = hosts

    def choose(self):
        for host in self._hosts:
            yield host


def force_unicode(s):
    if isinstance(s, bytes):
        try:
            return s.decode('utf8')
        except UnicodeDecodeError as e:
            raise DatabaseError(e)
    else:
        return s


def tds_quote_id(id):
    """ Quote an identifier

    :param id: id to quote
    :returns: Quoted identifier
    """
    return '[{0}]'.format(id.replace(']', ']]'))


def tds7_crypt_pass(password):
    """ Mangle password according to tds rules

    :param password: Password str
    :returns: Byte-string with encoded password
    """
    encoded = bytearray(ucs2_codec.encode(password)[0])
    for i, ch in enumerate(encoded):
        encoded[i] = ((ch << 4) & 0xff | (ch >> 4)) ^ 0xA5
    return encoded


def total_seconds(td):
    """ Total number of seconds in timedelta object

    Python 2.6 doesn't have total_seconds method, this function
    provides a backport
    """
    return td.days * 24 * 60 * 60 + td.seconds


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

    def _ord(val):
        return val

else:
    exc_base_class = StandardError

    def _ord(val):
        return ord(val)


def _decode_num(buf):
    """ Decodes little-endian integer from buffer

    Buffer can be of any size
    """
    return reduce(lambda acc, val: acc * 256 + _ord(val), reversed(buf), 0)


# exception hierarchy
class Warning(exc_base_class):
    pass


class Error(exc_base_class):
    pass


TimeoutError = socket.timeout


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


class ClosedConnectionError(InterfaceError):
    def __init__(self):
        super(ClosedConnectionError, self).__init__('Server closed connection')


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

# standard dbapi type objects
STRING = DBAPITypeObject(SYBVARCHAR, SYBCHAR, SYBTEXT,
                         XSYBNVARCHAR, XSYBNCHAR, SYBNTEXT,
                         XSYBVARCHAR, XSYBCHAR, SYBMSXML)
BINARY = DBAPITypeObject(SYBIMAGE, SYBBINARY, SYBVARBINARY, XSYBVARBINARY, XSYBBINARY)
NUMBER = DBAPITypeObject(SYBBIT, SYBBITN, SYBINT1, SYBINT2, SYBINT4, SYBINT8, SYBINTN,
                         SYBREAL, SYBFLT8, SYBFLTN)
DATETIME = DBAPITypeObject(SYBDATETIME, SYBDATETIME4, SYBDATETIMN)
DECIMAL = DBAPITypeObject(SYBMONEY, SYBMONEY4, SYBMONEYN, SYBNUMERIC,
                          SYBDECIMAL)
ROWID = DBAPITypeObject()

# non-standard, but useful type objects
INTEGER = DBAPITypeObject(SYBBIT, SYBBITN, SYBINT1, SYBINT2, SYBINT4, SYBINT8, SYBINTN)
REAL = DBAPITypeObject(SYBREAL, SYBFLT8, SYBFLTN)
XML = DBAPITypeObject(SYBMSXML)


# stored procedure output parameter
class output(object):
    @property
    def type(self):
        """
        This is either the sql type declaration or python type instance
        of the parameter.
        """
        return self._type

    @property
    def value(self):
        """
        This is the value of the parameter.
        """
        return self._value

    def __init__(self, value=None, param_type=None):
        """ Creates procedure output parameter.
        
        :param param_type: either sql type declaration or python type
        :param value: value to pass into procedure
        """
        if param_type is None:
            if value is None or value is default:
                raise ValueError('Output type cannot be autodetected')
        elif isinstance(param_type, type) and value is not None:
            if value is not default and not isinstance(value, param_type):
                raise ValueError('value should match param_type', value, param_type)
        self._type = param_type
        self._value = value


class Binary(bytes):
    def __repr__(self):
        return 'Binary({0})'.format(super(Binary, self).__repr__())


class _Default(object):
    pass

default = _Default()


class InternalProc(object):
    def __init__(self, proc_id, name):
        self.proc_id = proc_id
        self.name = name

    def __unicode__(self):
        return self.name

SP_EXECUTESQL = InternalProc(TDS_SP_EXECUTESQL, 'sp_executesql')


class _TdsEnv:
    pass


def skipall(stm, size):
    """ Skips exactly size bytes in stm

    If EOF is reached before size bytes are skipped
    will raise :class:`ClosedConnectionError`

    :param stm: Stream to skip bytes in, should have read method
                this read method can return less than requested
                number of bytes.
    :param size: Number of bytes to skip.
    """
    res = stm.read(size)
    if len(res) == size:
        return
    elif len(res) == 0:
        raise ClosedConnectionError()
    left = size - len(res)
    while left:
        buf = stm.read(left)
        if len(buf) == 0:
            raise ClosedConnectionError()
        left -= len(buf)


def read_chunks(stm, size):
    """ Reads exactly size bytes from stm and produces chunks

    May call stm.read multiple times until required
    number of bytes is read.
    If EOF is reached before size bytes are read
    will raise :class:`ClosedConnectionError`

    :param stm: Stream to read bytes from, should have read method,
                this read method can return less than requested
                number of bytes.
    :param size: Number of bytes to read.
    """
    if size == 0:
        yield b''
        return

    res = stm.read(size)
    if len(res) == 0:
        raise ClosedConnectionError()
    yield res
    left = size - len(res)
    while left:
        buf = stm.read(left)
        if len(buf) == 0:
            raise ClosedConnectionError()
        yield buf
        left -= len(buf)


def readall(stm, size):
    """ Reads exactly size bytes from stm

    May call stm.read multiple times until required
    number of bytes read.
    If EOF is reached before size bytes are read
    will raise :class:`ClosedConnectionError`

    :param stm: Stream to read bytes from, should have read method
                this read method can return less than requested
                number of bytes.
    :param size: Number of bytes to read.
    :returns: Bytes buffer of exactly given size.
    """
    return b''.join(read_chunks(stm, size))


def readall_fast(stm, size):
    """
    Slightly faster version of readall, it reads no more than two chunks.
    Meaning that it can only be used to read small data that doesn't span
    more that two packets.

    :param stm: Stream to read from, should have read method.
    :param size: Number of bytes to read.
    :return:
    """
    buf, offset = stm.read_fast(size)
    if len(buf) - offset < size:
        # slow case
        buf = buf[offset:]
        buf += stm.read(size - len(buf))
        return buf, 0
    return buf, offset


class _TdsReader(object):
    """ TDS stream reader

    Provides stream-like interface for TDS packeted stream.
    Also provides convinience methods to decode primitive data like
    different kinds of integers etc.
    """
    def __init__(self, session):
        self._buf = ''
        self._pos = 0  # position in the buffer
        self._have = 0  # number of bytes read from packet
        self._size = 0  # size of current packet
        self._session = session
        self._transport = session._transport
        self._type = None
        self._status = None

    @property
    def session(self):
        """ Link to :class:`_TdsSession` object
        """
        return self._session

    @property
    def packet_type(self):
        """ Type of current packet

        Possible values are TDS_QUERY, TDS_LOGIN, etc.
        """
        return self._type

    def read_fast(self, size):
        """ Faster version of read

        Instead of returning sliced buffer it returns reference to internal
        buffer and the offset to this buffer.

        :param size: Number of bytes to read
        :returns: Tuple of bytes buffer, and offset in this buffer
        """
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
        """ Unpacks given structure from stream

        :param struct: A struct.Struct instance
        :returns: Result of unpacking
        """
        buf, offset = readall_fast(self, struct.size)
        return struct.unpack_from(buf, offset)

    def get_byte(self):
        """ Reads one byte from stream """
        return self.unpack(_byte)[0]

    def get_smallint(self):
        """ Reads 16bit signed integer from the stream """
        return self.unpack(_smallint_le)[0]

    def get_usmallint(self):
        """ Reads 16bit unsigned integer from the stream """
        return self.unpack(_usmallint_le)[0]

    def get_int(self):
        """ Reads 32bit signed integer from the stream """
        return self.unpack(_int_le)[0]

    def get_uint(self):
        """ Reads 32bit unsigned integer from the stream """
        return self.unpack(_uint_le)[0]

    def get_uint_be(self):
        """ Reads 32bit unsigned big-endian integer from the stream """
        return self.unpack(_uint_be)[0]

    def get_uint8(self):
        """ Reads 64bit unsigned integer from the stream """
        return self.unpack(_uint8_le)[0]

    def get_int8(self):
        """ Reads 64bit signed integer from the stream """
        return self.unpack(_int8_le)[0]

    def read_ucs2(self, num_chars):
        """ Reads num_chars UCS2 string from the stream """
        buf = readall(self, num_chars * 2)
        return ucs2_codec.decode(buf)[0]

    def read_str(self, size, codec):
        """ Reads byte string from the stream and decodes it

        :param size: Size of string in bytes
        :param codec: Instance of codec to decode string
        :returns: Unicode string
        """
        return codec.decode(readall(self, size))[0]

    def get_collation(self):
        """ Reads :class:`Collation` object from stream """
        buf = readall(self, Collation.wire_size)
        return Collation.unpack(buf)

    def unget_byte(self):
        """ Returns one last read byte to stream

        Can only be called once per read byte.
        """
        # this is a one trick pony...don't call it twice
        assert self._pos > 0
        self._pos -= 1

    def peek(self):
        """ Returns next byte from stream without consuming it
        """
        res = self.get_byte()
        self.unget_byte()
        return res

    def read(self, size):
        """ Reads size bytes from buffer

        May return fewer bytes than requested
        :param size: Number of bytes to read
        :returns: Bytes buffer, possibly shorter than requested,
                  returns empty buffer in case of EOF
        """
        buf, offset = self.read_fast(size)
        return buf[offset:offset + size]

    def _read_packet(self):
        """ Reads next TDS packet from the underlying transport

        If timeout is happened during reading of packet's header will
        cancel current request.
        Can only be called when transport's read pointer is at the begining
        of the packet.
        """
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
        """ Reads single packet and returns bytes payload of the packet

        Can only be called when transport's read pointer is at the beginning
        of the packet.
        """
        self._read_packet()
        return readall(self, self._size - _header.size)


class _TdsWriter(object):
    """ TDS stream writer

    Handles splitting of incoming data into TDS packets according to TDS protocol.
    Provides convinience methods for writing primitive data types.
    """
    def __init__(self, session, bufsize):
        self._session = session
        self._tds = session
        self._transport = session
        self._pos = 0
        self._buf = bytearray(bufsize)
        self._packet_no = 0

    @property
    def session(self):
        """ Back reference to parent :class:`_TdsSession` object """
        return self._session

    @property
    def bufsize(self):
        """ Size of the buffer """
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
        """ Starts new packet stream

        :param packet_type: Type of TDS stream, e.g. TDS_PRELOGIN, TDS_QUERY etc.
        """
        self._type = packet_type
        self._pos = 8

    def pack(self, struct, *args):
        """ Packs and writes structure into stream """
        self.write(struct.pack(*args))

    def put_byte(self, value):
        """ Writes single byte into stream """
        self.pack(_byte, value)

    def put_smallint(self, value):
        """ Writes 16-bit signed integer into the stream """
        self.pack(_smallint_le, value)

    def put_usmallint(self, value):
        """ Writes 16-bit unsigned integer into the stream """
        self.pack(_usmallint_le, value)

    def put_smallint_be(self, value):
        """ Writes 16-bit signed big-endian integer into the stream """
        self.pack(_smallint_be, value)

    def put_usmallint_be(self, value):
        """ Writes 16-bit unsigned big-endian integer into the stream """
        self.pack(_usmallint_be, value)

    def put_int(self, value):
        """ Writes 32-bit signed integer into the stream """
        self.pack(_int_le, value)

    def put_uint(self, value):
        """ Writes 32-bit unsigned integer into the stream """
        self.pack(_uint_le, value)

    def put_int_be(self, value):
        """ Writes 32-bit signed big-endian integer into the stream """
        self.pack(_int_be, value)

    def put_uint_be(self, value):
        """ Writes 32-bit unsigned big-endian integer into the stream """
        self.pack(_uint_be, value)

    def put_int8(self, value):
        """ Writes 64-bit signed integer into the stream """
        self.pack(_int8_le, value)

    def put_uint8(self, value):
        """ Writes 64-bit unsigned integer into the stream """
        self.pack(_uint8_le, value)

    def put_collation(self, collation):
        """ Writes :class:`Collation` structure into the stream """
        self.write(collation.pack())

    def write(self, data):
        """ Writes given bytes buffer into the stream

        Function returns only when entire buffer is written
        """
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
        """ Write string encoding it in UCS2 into stream """
        self.write_string(s, ucs2_codec)

    def write_string(self, s, codec):
        """ Write string encoding it with codec into stream """
        for i in xrange(0, len(s), self.bufsize):
            chunk = s[i:i + self.bufsize]
            buf, consumed = codec.encode(chunk)
            assert consumed == len(chunk)
            self.write(buf)

    def flush(self):
        """ Closes current packet stream """
        return self._write_packet(final=True)

    def _write_packet(self, final):
        """ Writes single TDS packet into underlying transport.

        Data for the packet is taken from internal buffer.

        :param final: True means this is the final packet in substream.
        """
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
    """ Base type for TDS data types.

    All TDS types should derive from it.
    In addition actual types should provide the following:

    - type - class variable storing type identifier
    """
    def get_typeid(self):
        """ Returns type identifier of type. """
        return self.type

    def get_declaration(self):
        """ Returns SQL declaration for this type.
        
        Examples are: NVARCHAR(10), TEXT, TINYINT
        Should be implemented in actual types.
        """
        raise NotImplementedError

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        """ Class method that parses declaration and returns a type instance.

        :param declaration: type declaration string
        :param nullable: true if type have to be nullable, false otherwise
        :param connection: instance of :class:`_TdsSocket`
        :return: If declaration is parsed, returns type instance,
                 otherwise returns None.

        Should be implemented in actual types.
        """
        raise NotImplementedError

    @classmethod
    def from_stream(cls, r):
        """ Class method that reads and returns a type instance.

        :param r: An instance of :class:`_TdsReader` to read type from.

        Should be implemented in actual types.
        """
        raise NotImplementedError

    def write_info(self, w):
        """ Writes type info into w stream.

        :param w: An instance of :class:`_TdsWriter` to write into.

        Should be symmetrical to from_stream method.
        Should be implemented in actual types.
        """
        raise NotImplementedError

    def write(self, w, value):
        """ Writes type's value into stream

        :param w: An instance of :class:`_TdsWriter` to write into.
        :param value: A value to be stored, should be compatible with the type

        Should be implemented in actual types.
        """
        raise NotImplementedError

    def read(self, r):
        """ Reads value from the stream.

        :param r: An instance of :class:`_TdsReader` to read value from.
        :return: A read value.

        Should be implemented in actual types.
        """
        raise NotImplementedError

    
class BasePrimitiveType(BaseType):
    """ Base type for primitive TDS data types.

    Primitive type is a fixed size type with no type arguments.
    All primitive TDS types should derive from it.
    In addition actual types should provide the following:

    - type - class variable storing type identifier
    - declaration - class variable storing name of sql type
    - isntance - class variable storing instance of class
    """

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if not nullable and declaration == cls.declaration:
            return cls.instance

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def write_info(self, w):
        pass


class BaseTypeN(BaseType):
    """ Base type for nullable TDS data types.

    All nullable TDS types should derive from it.
    In addition actual types should provide the following:

    - type - class variable storing type identifier
    - subtypes - class variable storing dict {subtype_size: subtype_instance}
    """

    def __init__(self, size):
        assert size in self.subtypes
        self._size = size
        self._current_subtype = self.subtypes[size]

    def get_typeid(self):
        return self._current_subtype.get_typeid()

    def get_declaration(self):
        return self._current_subtype.get_declaration()

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if nullable:
            for size, subtype in cls.subtypes.items():
                inst = subtype.from_declaration(declaration, False, connection)
                if inst:
                    return cls(size)
    
    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size not in cls.subtypes:
            raise InterfaceError('Invalid %s size' % cls.type, size)
        return cls(size)

    def write_info(self, w):
        w.put_byte(self._size)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size not in self.subtypes:
            raise r.session.bad_stream('Invalid %s size' % self.type, size)
        return self.subtypes[size].read(r)

    def write(self, w, val):
        if val is None:
            w.put_byte(0)
            return
        w.put_byte(self._size)
        self._current_subtype.write(w, val)

class Bit(BasePrimitiveType):
    type = SYBBIT
    declaration = 'BIT'

    def write(self, w, value):
        w.put_byte(1 if value else 0)

    def read(self, r):
        return bool(r.get_byte())

Bit.instance = Bit()


class BitN(BaseTypeN):
    type = SYBBITN
    subtypes = {1 : Bit.instance}
    
BitN.instance = BitN(1)


class TinyInt(BasePrimitiveType):
    type = SYBINT1
    declaration = 'TINYINT'

    def write(self, w, val):
        w.put_byte(val)

    def read(self, r):
        return r.get_byte()
    
TinyInt.instance = TinyInt()


class SmallInt(BasePrimitiveType):
    type = SYBINT2
    declaration = 'SMALLINT'

    def write(self, w, val):
        w.put_smallint(val)

    def read(self, r):
        return r.get_smallint()
    
SmallInt.instance = SmallInt()


class Int(BasePrimitiveType):
    type = SYBINT4
    declaration = 'INT'

    def write(self, w, val):
        w.put_int(val)

    def read(self, r):
        return r.get_int()
    
Int.instance = Int()


class BigInt(BasePrimitiveType):
    type = SYBINT8
    declaration = 'BIGINT'

    def write(self, w, val):
        w.put_int8(val)

    def read(self, r):
        return r.get_int8()

BigInt.instance = BigInt()


class IntN(BaseTypeN):
    type = SYBINTN
    
    subtypes = {
        1: TinyInt.instance,
        2: SmallInt.instance,
        4: Int.instance,
        8: BigInt.instance,
        }

    
class Real(BasePrimitiveType):
    type = SYBREAL
    declaration = 'REAL'

    def write(self, w, val):
        w.pack(_flt4_struct, val)

    def read(self, r):
        return r.unpack(_flt4_struct)[0]
    
Real.instance = Real()


class Float(BasePrimitiveType):
    type = SYBFLT8
    declaration = 'FLOAT'

    def write(self, w, val):
        w.pack(_flt8_struct, val)

    def read(self, r):
        return r.unpack(_flt8_struct)[0]
    
Float.instance = Float()


class FloatN(BaseTypeN):
    type = SYBFLTN
    
    subtypes = {
        4: Real.instance,
        8: Float.instance,
        }

    
class VarChar70(BaseType):
    type = XSYBVARCHAR

    def __init__(self, size, codec):
        #if size <= 0 or size > 8000:
        #    raise DataError('Invalid size for VARCHAR field')
        self._size = size
        self._codec = codec

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        return cls(size, codec=r._session.conn.server_codec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'VARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.server_codec)

    def get_declaration(self):
        return 'VARCHAR({0})'.format(self._size)

    def write_info(self, w):
        w.put_smallint(self._size)
        #w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_smallint(-1)
        else:
            val = force_unicode(val)
            val, _ = self._codec.encode(val)
            w.put_smallint(len(val))
            #w.put_smallint(len(val))
            w.write(val)

    def read(self, r):
        size = r.get_smallint()
        if size < 0:
            return None
        return r.read_str(size, self._codec)


class VarChar71(VarChar70):
    def __init__(self, size, collation):
        super(VarChar71, self).__init__(size, codec=collation.get_codec())
        self._collation = collation

    @classmethod
    def from_stream(cls, r):
        size = r.get_smallint()
        collation = r.get_collation()
        return cls(size, collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'VARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)

    def write_info(self, w):
        super(VarChar71, self).write_info(w)
        w.put_collation(self._collation)


class VarChar72(VarChar71):
    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        collation = r.get_collation()
        if size == 0xffff:
            return VarCharMax(collation)
        return cls(size, collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'VARCHAR(MAX)':
            return VarCharMax(connection.collation)
        m = re.match(r'VARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)


class VarCharMax(VarChar72):
    def __init__(self, collation):
        super(VarChar72, self).__init__(0, collation)

    def get_declaration(self):
        return 'VARCHAR(MAX)'

    def write_info(self, w):
        w.put_usmallint(PLP_MARKER)
        w.put_collation(self._collation)

    def write(self, w, val):
        if val is None:
            w.put_uint8(PLP_NULL)
        else:
            val = force_unicode(val)
            val, _ = self._codec.encode(val)
            w.put_int8(len(val))
            if len(val) > 0:
                w.put_int(len(val))
                w.write(val)
            w.put_int(0)

    def read(self, r):
        r = PlpReader(r)
        if r.is_null():
            return None
        return ''.join(iterdecode(r.chunks(), self._codec))


class NVarChar70(BaseType):
    type = XSYBNVARCHAR

    def __init__(self, size):
        #if size <= 0 or size > 4000:
        #    raise DataError('Invalid size for NVARCHAR field')
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        return cls(size / 2)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'NVARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

    def get_declaration(self):
        return 'NVARCHAR({0})'.format(self._size)

    def write_info(self, w):
        w.put_usmallint(self._size * 2)
        #w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_usmallint(0xffff)
        else:
            if isinstance(val, bytes):
                val = force_unicode(val)
            buf, _ = ucs2_codec.encode(val)
            l = len(buf)
            w.put_usmallint(l)
            w.write(buf)

    def read(self, r):
        size = r.get_usmallint()
        if size == 0xffff:
            return None
        return r.read_str(size, ucs2_codec)


class NVarChar71(NVarChar70):
    def __init__(self, size, collation=raw_collation):
        super(NVarChar71, self).__init__(size)
        self._collation = collation

    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        collation = r.get_collation()
        return cls(size / 2, collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'NVARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)

    def write_info(self, w):
        super(NVarChar71, self).write_info(w)
        w.put_collation(self._collation)


class NVarChar72(NVarChar71):
    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        collation = r.get_collation()
        if size == 0xffff:
            return NVarCharMax(size, collation)
        return cls(size / 2, collation=collation)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'NVARCHAR(MAX)':
            return VarCharMax(connection.collation)
        m = re.match(r'NVARCHAR\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)), connection.collation)


class NVarCharMax(NVarChar72):
    def get_typeid(self):
        return SYBNTEXT

    def get_declaration(self):
        return 'NVARCHAR(MAX)'

    def write_info(self, w):
        w.put_usmallint(PLP_MARKER)
        w.put_collation(self._collation)

    def write(self, w, val):
        if val is None:
            w.put_uint8(PLP_NULL)
        else:
            if isinstance(val, bytes):
                val = force_unicode(val)
            val, _ = ucs2_codec.encode(val)
            w.put_uint8(len(val))
            if len(val) > 0:
                w.put_uint(len(val))
                w.write(val)
            w.put_uint(0)

    def read(self, r):
        r = PlpReader(r)
        if r.is_null():
            return None
        res = ''.join(iterdecode(r.chunks(), ucs2_codec))
        return res


class Xml(NVarCharMax):
    type = SYBMSXML
    declaration = 'XML'

    def __init__(self, schema={}):
        super(Xml, self).__init__(0)
        self._schema = schema

    def get_typeid(self):
        return self.type

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_stream(cls, r):
        has_schema = r.get_byte()
        schema = {}
        if has_schema:
            schema['dbname'] = r.read_ucs2(r.get_byte())
            schema['owner'] = r.read_ucs2(r.get_byte())
            schema['collection'] = r.read_ucs2(r.get_smallint())
        return cls(schema)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()

    def write_info(self, w):
        if self._schema:
            w.put_byte(1)
            w.put_byte(len(self._schema['dbname']))
            w.write_ucs2(self._schema['dbname'])
            w.put_byte(len(self._schema['owner']))
            w.write_ucs2(self._schema['owner'])
            w.put_usmallint(len(self._schema['collection']))
            w.write_ucs2(self._schema['collection'])
        else:
            w.put_byte(0)


class Text70(BaseType):
    type = SYBTEXT
    declaration = 'TEXT'

    def __init__(self, size=0, table_name='', codec=None):
        self._size = size
        self._table_name = table_name
        self._codec = codec

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name, codec=r.session.conn.server_codec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()
    
    def get_declaration(self):
        return self.declaration

    def write_info(self, w):
        w.put_int(self._size)

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
        else:
            val = force_unicode(val)
            val, _ = self._codec.encode(val)
            w.put_int(len(val))
            w.write(val)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        readall(r, size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, self._codec)


class Text71(Text70):
    def __init__(self, size=0, table_name='', collation=raw_collation):
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
        w.put_int(self._size)
        w.put_collation(self._collation)


class Text72(Text71):
    def __init__(self, size=0, table_name_parts=[], collation=raw_collation):
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


class NText70(BaseType):
    type = SYBNTEXT
    declaration = 'NTEXT'

    def __init__(self, size=0, table_name=''):
        self._size = size
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()
    
    def get_declaration(self):
        return self.declaration

    def read(self, r):
        textptr_size = r.get_byte()
        if textptr_size == 0:
            return None
        readall(r, textptr_size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, ucs2_codec)

    def write_info(self, w):
        w.put_int(self._size * 2)

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
        else:
            w.put_int(len(val) * 2)
            w.write_ucs2(val)


class NText71(NText70):
    def __init__(self, size=0, table_name='', collation=raw_collation):
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
        w.put_int(self._size)
        w.put_collation(self._collation)

    def read(self, r):
        textptr_size = r.get_byte()
        if textptr_size == 0:
            return None
        readall(r, textptr_size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, ucs2_codec)


class NText72(NText71):
    def __init__(self, size=0, table_name_parts=[], collation=raw_collation):
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
        size = r.get_usmallint()
        return cls(size)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'VARBINARY\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))
    
    def get_declaration(self):
        return 'VARBINARY({0})'.format(self._size)

    def write_info(self, w):
        w.put_usmallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_usmallint(0xffff)
        else:
            w.put_usmallint(len(val))
            w.write(val)

    def read(self, r):
        size = r.get_usmallint()
        if size == 0xffff:
            return None
        return readall(r, size)


class VarBinary72(VarBinary):
    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        if size == 0xffff:
            return VarBinaryMax()
        return cls(size)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'VARBINARY(MAX)':
            return VarBinaryMax()
        m = re.match(r'VARBINARY\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))


class VarBinaryMax(VarBinary):
    def __init__(self):
        super(VarBinaryMax, self).__init__(0)

    def get_declaration(self):
        return 'VARBINARY(MAX)'

    def write_info(self, w):
        w.put_usmallint(PLP_MARKER)

    def write(self, w, val):
        if val is None:
            w.put_uint8(PLP_NULL)
        else:
            w.put_uint8(len(val))
            if val:
                w.put_uint(len(val))
                w.write(val)
            w.put_uint(0)

    def read(self, r):
        r = PlpReader(r)
        if r.is_null():
            return None
        return b''.join(r.chunks())


class Image70(BaseType):
    type = SYBIMAGE
    declaration = 'IMAGE'

    def __init__(self, size=0, table_name=''):
        self._table_name = table_name
        self._size = size

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls()

    def read(self, r):
        size = r.get_byte()
        if size == 16:  # Jeff's hack
            readall(r, 16)  # textptr
            readall(r, 8)  # timestamp
            colsize = r.get_int()
            return readall(r, colsize)
        else:
            return None

    def write(self, w, val):
        if val is None:
            w.put_int(-1)
            return
        w.put_int(len(val))
        w.write(val)

    def write_info(self, w):
        w.put_int(self._size)


class Image72(Image70):
    def __init__(self, size=0, parts=[]):
        self._parts = parts
        self._size = size

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        num_parts = r.get_byte()
        parts = []
        for _ in range(num_parts):
            parts.append(r.read_ucs2(r.get_usmallint()))
        return Image72(size, parts)


class BaseDateTime(BaseType):
    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)


class SmallDateTime(BasePrimitiveType, BaseDateTime):
    type = SYBDATETIME4
    declaration = 'SMALLDATETIME'

    _max_date = datetime(2079, 6, 6, 23, 59, 0)
    _struct = struct.Struct('<HH')

    def write(self, w, val):
        if val.tzinfo:
            if not w.session.use_tz:
                raise DataError('Timezone-aware datetime is used without specifying use_tz')
            val = val.astimezone(w.session.use_tz).replace(tzinfo=None)
        days = (val - self._base_date).days
        minutes = val.hour * 60 + val.minute
        w.pack(self._struct, days, minutes)

    def read(self, r):
        days, minutes = r.unpack(self._struct)
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        return (self._base_date + timedelta(days=days, minutes=minutes)).replace(tzinfo=tzinfo)
    
SmallDateTime.instance = SmallDateTime()


class DateTime(BasePrimitiveType, BaseDateTime):
    type = SYBDATETIME
    declaration = 'DATETIME'

    _struct = struct.Struct('<ll')
    
    def write(self, w, val):
        if val.tzinfo:
            if not w.session.use_tz:
                raise DataError('Timezone-aware datetime is used without specifying use_tz')
            val = val.astimezone(w.session.use_tz).replace(tzinfo=None)
        w.write(self.encode(val))

    def read(self, r):
        days, t = r.unpack(self._struct)
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        return _applytz(self.decode(days, t), tzinfo)

    @classmethod
    def validate(cls, value):
        if not (cls._min_date <= value <= cls._max_date):
            raise DataError('Date is out of range')

    @classmethod
    def encode(cls, value):
        #cls.validate(value)
        if type(value) == date:
            value = datetime.combine(value, time(0, 0, 0))
        days = (value - cls._base_date).days
        ms = value.microsecond // 1000
        tm = (value.hour * 60 * 60 + value.minute * 60 + value.second) * 300 + int(round(ms * 3 / 10.0))
        return cls._struct.pack(days, tm)

    @classmethod
    def decode(cls, days, time):
        ms = int(round(time % 300 * 10 / 3.0))
        secs = time // 300
        return cls._base_date + timedelta(days=days, seconds=secs, milliseconds=ms)
    
DateTime.instance = DateTime()


class DateTimeN(BaseTypeN, BaseDateTime):
    type = SYBDATETIMN
    subtypes = {
        4: SmallDateTime.instance,
        8: DateTime.instance,
        }


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


class MsDate(BasePrimitiveType, BaseDateTime73):
    type = SYBMSDATE
    declaration = 'DATE'

    MIN = date(1, 1, 1)
    MAX = date(9999, 12, 31)

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

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        m = re.match(r'TIME\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

    def get_declaration(self):
        return 'TIME({0})'.format(self._prec)

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
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        return self._read_time(r, size, self._prec, tzinfo)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


class DateTime2(BaseDateTime73):
    type = SYBMSDATETIME2

    def __init__(self, prec=7):
        self._prec = prec
        self._size = self._precision_to_len[prec] + 3

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    def get_declaration(self):
        return 'DATETIME2({0})'.format(self._prec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'DATETIME2':
            return cls()
        m = re.match(r'DATETIME2\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))

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
        tzinfo = None
        if r.session.tzinfo_factory is not None:
            tzinfo = r.session.tzinfo_factory(0)
        time = self._read_time(r, size - 3, self._prec, tzinfo)
        date = self._read_date(r)
        return datetime.combine(date, time)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        return self.read_fixed(r, size)


class DateTimeOffset(BaseDateTime73):
    type = SYBMSDATETIMEOFFSET

    def __init__(self, prec=7):
        self._prec = prec
        self._size = self._precision_to_len[prec] + 5

    @classmethod
    def from_stream(cls, r):
        prec = r.get_byte()
        return cls(prec)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'DATETIMEOFFSET':
            return cls()
        m = re.match(r'DATETIMEOFFSET\((\d+)\)', declaration)
        if m:
            return cls(int(m.group(1)))
    
    def get_declaration(self):
        return 'DATETIMEOFFSET({0})'.format(self._prec)

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
            w.put_smallint(int(total_seconds(utcoffset)) // 60)

    def read_fixed(self, r, size):
        time = self._read_time(r, size - 5, self._prec, _utc)
        date = self._read_date(r)
        offset = r.get_smallint()
        tzinfo_factory = r._session.tzinfo_factory
        if tzinfo_factory is None:
            from .tz import FixedOffsetTimezone
            tzinfo_factory = FixedOffsetTimezone
        tz = tzinfo_factory(offset)
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

    def __init__(self, scale=0, prec=18):
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

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == 'DECIMAL':
            return cls()
        m = re.match(r'DECIMAL\((\d+),\s*(\d+)\)', declaration)
        if m:
            return cls(int(m.group(2)), int(m.group(1)))

    def get_declaration(self):
        return 'DECIMAL({0},{1})'.format(self._prec, self._scale)

    def write_info(self, w):
        w.pack(self._info_struct, self._size, self._prec, self._scale)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
            return
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


class Money4(BasePrimitiveType):
    type = SYBMONEY4
    declaration = 'SMALLMONEY'

    def read(self, r):
        return Decimal(r.get_int()) / 10000

    def write(self, w, val):
        val = int(val * 10000)
        w.put_int(val)

Money4.instance = Money4()


class Money8(BasePrimitiveType):
    type = SYBMONEY
    declaration = 'MONEY'
    
    _struct = struct.Struct('<lL')

    def read(self, r):
        hi, lo = r.unpack(self._struct)
        val = hi * (2 ** 32) + lo
        return Decimal(val) / 10000

    def write(self, w, val):
        val = val * 10000
        hi = int(val // (2 ** 32))
        lo = int(val % (2 ** 32))
        w.pack(self._struct, hi, lo)

Money8.instance = Money8()


class MoneyN(BaseTypeN):
    type = SYBMONEYN
    
    subtypes = {
        4: Money4.instance,
        8: Money8.instance,
        }

class MsUnique(BaseType):
    type = SYBUNIQUE
    declaration = 'UNIQUEIDENTIFIER'

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size != 16:
            raise InterfaceError('Invalid size of UNIQUEIDENTIFIER field')
        return cls.instance

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls.instance

    def get_declaration(self):
        return self.declaration

    def write_info(self, w):
        w.put_byte(16)

    def write(self, w, value):
        if value is None:
            w.put_byte(0)
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
    declaration = 'SQL_VARIANT'

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

    def get_declaration(self):
        return self.declaration

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        return Variant(size)

    @classmethod
    def from_declaration(cls, declaration, nullable, connection):
        if declaration == cls.declaration:
            return cls(0)

    def write_info(self, w):
        w.put_int(self._size)

    def read(self, r):
        size = r.get_int()
        if size == 0:
            return None

        type_id = r.get_byte()
        prop_bytes = r.get_byte()
        type_factory = self._type_map.get(type_id)
        if not type_factory:
            r.session.bad_stream('Variant type invalid', type_id)
        return type_factory(r, size - prop_bytes - 2)

    def write(self, w, val):
        if val is None:
            w.put_int(0)
            return
        raise NotImplementedError


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
    SYBTEXT: Text70,
    SYBNTEXT: NText70,
    SYBMSXML: Xml,
    XSYBBINARY: VarBinary,
    XSYBVARBINARY: VarBinary,
    SYBIMAGE: Image70,
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


def _create_exception_by_message(msg, custom_error_msg = None):
    msg_no = msg['msgno']
    if custom_error_msg is not None:
        error_msg = custom_error_msg
    else:
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
    return ex


class _TdsSession(object):
    """ TDS session

    Represents a single TDS session within MARS connection, when MARS enabled there could be multiple TDS sessions
    within one connection.
    """
    def __init__(self, tds, transport, tzinfo_factory):
        self.out_pos = 8
        self.res_info = None
        self.in_cancel = False
        self.wire_mtx = None
        self.param_info = None
        self.has_status = False
        self.ret_status = None
        self.skipped_to_status = False
        self._transport = transport
        self._reader = _TdsReader(self)
        self._reader._transport = transport
        self._writer = _TdsWriter(self, tds._bufsize)
        self._writer._transport = transport
        self.in_buf_max = 0
        self.state = TDS_IDLE
        self._tds = tds
        self.messages = []
        self.chunk_handler = tds.chunk_handler
        self.rows_affected = -1
        self.use_tz = tds.use_tz
        self._spid = 0
        self.tzinfo_factory = tzinfo_factory

    def __repr__(self):
        fmt = "<_TdsSession state={} tds={} messages={} rows_affected={} use_tz={} spid={} in_cancel={}>"
        res = fmt.format(repr(self.state), repr(self._tds), repr(self.messages),
                         repr(self.rows_affected), repr(self.use_tz), repr(self._spid),
                         self.in_cancel)
        return res

    def raise_db_exception(self):
        """ Raises exception from last server message

        This function will skip messages: The statement has been terminated
        """
        if not self.messages:
            raise Error("Request failed, server didn't send error message")
        while True:
            msg = self.messages[-1]
            if msg['msgno'] == 3621:  # the statement has been terminated
                self.messages = self.messages[:-1]
            else:
                break

        error_msg = ' '.join(msg['message'] for msg in self.messages)
        ex = _create_exception_by_message(msg, error_msg)
        raise ex

    def get_type_info(self, curcol):
        """ Reads TYPE_INFO structure (http://msdn.microsoft.com/en-us/library/dd358284.aspx)

        :param curcol: An instance of :class:`Column` that will receive read information
        """
        r = self._reader
        # User defined data type of the column
        curcol.column_usertype = r.get_uint() if IS_TDS72_PLUS(self) else r.get_usmallint()
        curcol.flags = r.get_usmallint()  # Flags
        curcol.column_nullable = curcol.flags & Column.fNullable
        curcol.column_writeable = (curcol.flags & Column.fReadWrite) > 0
        curcol.column_identity = (curcol.flags & Column.fIdentity) > 0
        type_id = r.get_byte()
        type_class = self._tds._type_map.get(type_id)
        if not type_class:
            raise InterfaceError('Invalid type id', type_id)
        curcol.type = type_class.from_stream(r)

    def tds7_process_result(self):
        """ Reads and processes COLMETADATA stream

        This stream contains a list of returned columns.
        Stream format link: http://msdn.microsoft.com/en-us/library/dd357363.aspx
        """
        r = self._reader
        #logger.debug("processing TDS7 result metadata.")

        # read number of columns and allocate the columns structure

        num_cols = r.get_smallint()

        # This can be a DUMMY results token from a cursor fetch

        if num_cols == -1:
            #logger.debug("no meta data")
            return

        self.param_info = None
        self.has_status = False
        self.ret_status = None
        self.skipped_to_status = False
        self.rows_affected = TDS_NO_COUNT
        self.more_rows = True
        self.row = [None] * num_cols
        self.res_info = info = _Results()

        #
        # loop through the columns populating COLINFO struct from
        # server response
        #
        #logger.debug("setting up {0} columns".format(num_cols))
        header_tuple = []
        for col in range(num_cols):
            curcol = Column()
            info.columns.append(curcol)
            self.get_type_info(curcol)

            #
            # under 7.0 lengths are number of characters not
            # number of bytes... read_ucs2 handles this
            #
            curcol.column_name = r.read_ucs2(r.get_byte())
            precision = curcol.type.precision if hasattr(curcol.type, 'precision') else None
            scale = curcol.type.scale if hasattr(curcol.type, 'scale') else None
            size = curcol.type._size if hasattr(curcol.type, '_size') else None
            header_tuple.append((curcol.column_name, curcol.type.get_typeid(), None, size, precision, scale, curcol.column_nullable))
        info.description = tuple(header_tuple)
        return info

    def process_param(self):
        """ Reads and processes RETURNVALUE stream.

        This stream is used to send OUTPUT parameters from RPC to client.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd303881.aspx
        """
        r = self._reader
        if IS_TDS72_PLUS(self):
            ordinal = r.get_usmallint()
        else:
            r.get_usmallint()  # ignore size
            ordinal = self._out_params_indexes[self.return_value_index]
        name = r.read_ucs2(r.get_byte())
        r.get_byte()  # 1 - OUTPUT of sp, 2 - result of udf
        param = Column()
        param.column_name = name
        self.get_type_info(param)
        param.value = param.type.read(r)
        self.output_params[ordinal] = param
        self.return_value_index += 1

    def process_cancel(self):
        """
        Process the incoming token stream until it finds
        an end token DONE with the cancel flag set.
        At that point the connection should be ready to handle a new query.

        In case when no cancel request is pending this function does nothing.
        """
        # silly cases, nothing to do
        if not self.in_cancel:
            return

        while True:
            token_id = self.get_token_id()
            self.process_token(token_id)
            if not self.in_cancel:
                return

    def process_msg(self, marker):
        """ Reads and processes ERROR/INFO streams

        Stream formats:

        - ERROR: http://msdn.microsoft.com/en-us/library/dd304156.aspx
        - INFO: http://msdn.microsoft.com/en-us/library/dd303398.aspx

        :param marker: TDS_ERROR_TOKEN or TDS_INFO_TOKEN
        """
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
                    self.process_token(next_marker)
                else:
                    break
            r.unget_byte()

        # special case
        self.messages.append(msg)

    def process_row(self):
        """ Reads and handles ROW stream.

        This stream contains list of values of one returned row.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd357254.aspx
        """
        r = self._reader
        info = self.res_info
        info.row_count += 1
        for i, curcol in enumerate(info.columns):
            curcol.value = self.row[i] = curcol.type.read(r)

    def process_nbcrow(self):
        """ Reads and handles NBCROW stream.

        This stream contains list of values of one returned row in a compressed way,
        introduced in TDS 7.3.B
        Stream format url: http://msdn.microsoft.com/en-us/library/dd304783.aspx
        """
        r = self._reader
        info = self.res_info
        if not info:
            self.bad_stream('got row without info')
        assert len(info.columns) > 0
        info.row_count += 1

        # reading bitarray for nulls, 1 represent null values for
        # corresponding fields
        nbc = readall(r, (len(info.columns) + 7) // 8)
        for i, curcol in enumerate(info.columns):
            if _ord(nbc[i // 8]) & (1 << (i % 8)):
                value = None
            else:
                value = curcol.type.read(r)
            self.row[i] = value

    def process_orderby(self):
        """ Reads and processes ORDER stream

        Used to inform client by which column dataset is ordered.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd303317.aspx
        """
        r = self._reader
        skipall(r, r.get_smallint())

    def process_orderby2(self):
        r = self._reader
        skipall(r, r.get_int())

    def process_end(self, marker):
        """ Reads and processes DONE/DONEINPROC/DONEPROC streams

        Stream format urls:

        - DONE: http://msdn.microsoft.com/en-us/library/dd340421.aspx
        - DONEINPROC: http://msdn.microsoft.com/en-us/library/dd340553.aspx
        - DONEPROC: http://msdn.microsoft.com/en-us/library/dd340753.aspx

        :param marker: Can be TDS_DONE_TOKEN or TDS_DONEINPROC_TOKEN or TDS_DONEPROC_TOKEN
        """
        self.more_rows = False
        r = self._reader
        status = r.get_usmallint()
        r.get_usmallint()  # cur_cmd
        more_results = status & TDS_DONE_MORE_RESULTS != 0
        was_cancelled = status & TDS_DONE_CANCELLED != 0
        #error = status & TDS_DONE_ERROR != 0
        done_count_valid = status & TDS_DONE_COUNT != 0
        #logger.debug(
        #    'process_end: more_results = {0}\n'
        #    '\t\twas_cancelled = {1}\n'
        #    '\t\terror = {2}\n'
        #    '\t\tdone_count_valid = {3}'.format(more_results, was_cancelled, error, done_count_valid))
        if self.res_info:
            self.res_info.more_results = more_results
        rows_affected = r.get_int8() if IS_TDS72_PLUS(self) else r.get_int()
        #logger.debug('\t\trows_affected = {0}'.format(rows_affected))
        if was_cancelled or (not more_results and not self.in_cancel):
            #logger.debug('process_end() state set to TDS_IDLE')
            self.in_cancel = False
            self.set_state(TDS_IDLE)
        if done_count_valid:
            self.rows_affected = rows_affected
        else:
            self.rows_affected = -1
        self.done_flags = status
        if self.done_flags & TDS_DONE_ERROR and not was_cancelled and not self.in_cancel:
            self.raise_db_exception()

    def process_env_chg(self):
        """ Reads and processes ENVCHANGE stream.

        Stream info url: http://msdn.microsoft.com/en-us/library/dd303449.aspx
        """
        r = self._reader
        size = r.get_smallint()
        type = r.get_byte()
        #logger.debug("process_env_chg: type: {0}".format(type))
        if type == TDS_ENV_SQLCOLLATION:
            size = r.get_byte()
            #logger.debug("process_env_chg(): {0} bytes of collation data received".format(size))
            #logger.debug("self.collation was {0}".format(self.conn.collation))
            self.conn.collation = r.get_collation()
            skipall(r, size - 5)
            #tds7_srv_charset_changed(tds, tds.conn.collation)
            #logger.debug("self.collation now {0}".format(self.conn.collation))
            # discard old one
            skipall(r, r.get_byte())
        elif type == TDS_ENV_BEGINTRANS:
            size = r.get_byte()
            # TODO: parse transaction
            self.conn.tds72_transaction = r.get_uint8()
            skipall(r, r.get_byte())
        elif type == TDS_ENV_COMMITTRANS or type == TDS_ENV_ROLLBACKTRANS:
            self.conn.tds72_transaction = 0
            skipall(r, r.get_byte())
            skipall(r, r.get_byte())
        elif type == TDS_ENV_PACKSIZE:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
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
            r.read_ucs2(r.get_byte())
            self.conn.env.database = newval
        elif type == TDS_ENV_LANG:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            self.conn.env.language = newval
        elif type == TDS_ENV_CHARSET:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            #logger.debug("server indicated charset change to \"{0}\"\n".format(newval))
            self.conn.env.charset = newval
            remap = {'iso_1': 'iso8859-1'}
            self.conn.server_codec = codecs.lookup(remap.get(newval, newval))
            #tds_srv_charset_changed(self, newval)
        elif type == TDS_ENV_DB_MIRRORING_PARTNER:
            r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
        elif type == TDS_ENV_LCID:
            lcid = int(r.read_ucs2(r.get_byte()))
            self.conn.server_codec = codecs.lookup(lcid2charset(lcid))
            r.read_ucs2(r.get_byte())
        else:
            logger.warning("unknown env type: {0}, skipping".format(type))
            # discard byte values, not still supported
            skipall(r, size - 1)

    def process_auth(self):
        """ Reads and processes SSPI stream.

        Stream info: http://msdn.microsoft.com/en-us/library/dd302844.aspx
        """
        r = self._reader
        w = self._writer
        pdu_size = r.get_smallint()
        if not self.authentication:
            raise Error('Got unexpected token')
        packet = self.authentication.handle_next(readall(r, pdu_size))
        if packet:
            w.write(packet)
            w.flush()

    def is_connected(self):
        """
        :return: True if transport is connected
        """
        return self._transport.is_connected()

    def bad_stream(self, msg):
        """ Called when input stream contains unexpected data.

        Will close stream and raise :class:`InterfaceError`
        :param msg: Message for InterfaceError exception.
        :return: Never returns, always raises exception.
        """
        self.close()
        raise InterfaceError(msg)

    @property
    def tds_version(self):
        """ Returns integer encoded current TDS protocol version
        """
        return self._tds.tds_version

    @property
    def conn(self):
        """ Reference to owning :class:`_TdsSocket`
        """
        return self._tds

    def close(self):
        self._transport.close()

    def set_state(self, state):
        """ Switches state of the TDS session.

        It also does state transitions checks.
        :param state: New state, one of TDS_PENDING/TDS_READING/TDS_IDLE/TDS_DEAD/TDS_QUERING
        """
        prior_state = self.state
        if state == prior_state:
            return state
        if state == TDS_PENDING:
            if prior_state in (TDS_READING, TDS_QUERYING):
                self.state = TDS_PENDING
            else:
                raise InterfaceError('logic error: cannot chage query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
        elif state == TDS_READING:
            # transition to READING are valid only from PENDING
            if self.state != TDS_PENDING:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            else:
                self.state = state
        elif state == TDS_IDLE:
            if prior_state == TDS_DEAD:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            self.state = state
        elif state == TDS_DEAD:
            self.state = state
        elif state == TDS_QUERYING:
            if self.state == TDS_DEAD:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            elif self.state != TDS_IDLE:
                raise InterfaceError('logic error: cannot change query state from {0} to {1}'.
                                     format(state_names[prior_state], state_names[state]))
            else:
                self.rows_affected = TDS_NO_COUNT
                self.internal_sp_called = 0
                self.state = state
        else:
            assert False
        return self.state

    @contextmanager
    def querying_context(self, packet_type):
        """ Context manager for querying.

        Sets state to TDS_QUERYING, and reverts it to TDS_IDLE if exception happens inside managed block,
        and to TDS_PENDING if managed block succeeds and flushes buffer.
        """
        if self.set_state(TDS_QUERYING) != TDS_QUERYING:
            raise Error("Couldn't switch to state")
        self._writer.begin_packet(packet_type)
        try:
            yield
        except:
            if self.state != TDS_DEAD:
                self.set_state(TDS_IDLE)
            raise
        else:
            self.set_state(TDS_PENDING)
            self._writer.flush()

    def _autodetect_column_type(self, value, value_type):
        """ Function guesses type of the parameter from the type of value.

        :param value: value to be passed to db, can be None
        :param value_type: value type, if value is None, type is used instead of it
        :return: An instance of subclass of :class:`BaseType`
        """
        if value is None and value_type is None:
            return self.conn.NVarChar(1, collation=self.conn.collation)
        assert value_type is not None
        assert value is None or isinstance(value, value_type)
        
        if issubclass(value_type, bool):
            return BitN.instance
        elif issubclass(value_type, six.integer_types):
            if value == None:
                return IntN(8)
            if -2 ** 31 <= value <= 2 ** 31 - 1:
                return IntN(4)
            elif -2 ** 63 <= value <= 2 ** 63 - 1:
                return IntN(8)
            elif -10 ** 38 + 1 <= value <= 10 ** 38 - 1:
                return MsDecimal(0, 38)
            else:
                raise DataError('Numeric value out of range')
        elif issubclass(value_type, float):
            return FloatN(8)
        elif issubclass(value_type, Binary):
            return self.conn.long_binary_type()
        elif issubclass(value_type, six.binary_type):
            if self._tds.login.bytes_to_unicode:
                return self.conn.long_string_type(collation=self.conn.collation)
            else:
                return self.conn.long_varchar_type(collation=self.conn.collation)
        elif issubclass(value_type, six.string_types):
            return self.conn.long_string_type(collation=self.conn.collation)
        elif issubclass(value_type, datetime):
            if IS_TDS73_PLUS(self):
                if value != None and value.tzinfo and not self.use_tz:
                    return DateTimeOffset()
                else:
                    return DateTime2()
            else:
                return DateTimeN(8)
        elif issubclass(value_type, date):
            if IS_TDS73_PLUS(self):
                return MsDate.instance
            else:
                return DateTimeN(8)
        elif issubclass(value_type, time):
            if not IS_TDS73_PLUS(self):
                raise DataError('Time type is not supported on MSSQL 2005 and lower')
            return MsTime(6)
        elif issubclass(value_type, Decimal):
            if value != None:
                return MsDecimal.from_value(value)
            else:
                return MsDecimal()
        elif issubclass(value_type, uuid.UUID):
            return MsUnique.instance
        else:
            raise DataError('Parameter type is not supported: {!r} {!r}'.format(value, value_type))

    def make_param(self, name, value):
        """ Generates instance of :class:`Column` from value and name

        Value can also be of a special types:

        - An instance of :class:`Column`, in which case it is just returned.
        - An instance of :class:`output`, in which case parameter will become
          an output parameter.
        - A singleton :var:`default`, in which case default value will be passed
          into a stored proc.

        :param name: Name of the parameter, will populate column_name property of returned column.
        :param value: Value of the parameter, also used to guess the type of parameter.
        :return: An instance of :class:`Column`
        """
        if isinstance(value, Column):
            value.column_name = name
            return value
        column = Column()
        column.column_name = name
        column.flags = 0
        
        if isinstance(value, output):
            column.flags |= fByRefValue
            if isinstance(value.type, six.string_types):
                column.type = self._tds.type_by_declaration(value.type, True)
            value_type = value.type or type(value.value)
            value = value.value
        else:
            value_type = type(value)

        if value_type is type(None):
            value_type = None
            
        if value is default:
            column.flags |= fDefaultValue
            value = None
            if value_type is _Default:
                value_type = None

        column.value = value
        if column.type is None:
            column.type = self._autodetect_column_type(value, value_type)
        return column

    def _convert_params(self, parameters):
        """ Converts a dict of list of parameters into a list of :class:`Column` instances.

        :param parameters: Can be a list of parameter values, or a dict of parameter names to values.
        :return: A list of :class:`Column` instances.
        """
        if isinstance(parameters, dict):
            return [self.make_param(name, value)
                    for name, value in parameters.items()]
        else:
            params = []
            for parameter in parameters:
                params.append(self.make_param('', parameter))
            return params

    def cancel_if_pending(self):
        """ Cancels current pending request.

        Does nothing if no request is pending, otherwise sends cancel request,
        and waits for response.
        """
        if self.state == TDS_IDLE:
            return
        if not self.in_cancel:
            self._put_cancel()
        self.process_cancel()

    def submit_rpc(self, rpc_name, params, flags):
        """ Sends an RPC request.

        This call will transition session into pending state.
        If some operation is currently pending on the session, it will be
        cancelled before sending this request.

        Spec: http://msdn.microsoft.com/en-us/library/dd357576.aspx

        :param rpc_name: Name of the RPC to call, can be an instance of :class:`InternalProc`
        :param params: Stored proc parameters, should be a list of :class:`Column` instances.
        :param flags: See spec for possible flags.
        """
        self.messages = []
        self.output_params = {}
        self.cancel_if_pending()
        self.res_info = None
        w = self._writer
        with self.querying_context(TDS_RPC):
            self._START_QUERY()
            if IS_TDS71_PLUS(self) and isinstance(rpc_name, InternalProc):
                w.put_smallint(-1)
                w.put_smallint(rpc_name.proc_id)
            else:
                if isinstance(rpc_name, InternalProc):
                    rpc_name = rpc_name.name
                w.put_smallint(len(rpc_name))
                w.write_ucs2(rpc_name)
            #
            # TODO support flags
            # bit 0 (1 as flag) in TDS7/TDS5 is "recompile"
            # bit 1 (2 as flag) in TDS7+ is "no metadata" bit this will prevent sending of column infos
            #
            w.put_usmallint(flags)
            self._out_params_indexes = []
            for i, param in enumerate(params):
                if param.flags & fByRefValue:
                    self._out_params_indexes.append(i)
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

    def submit_plain_query(self, operation):
        """ Sends a plain query to server.

        This call will transition session into pending state.
        If some operation is currently pending on the session, it will be
        cancelled before sending this request.

        Spec: http://msdn.microsoft.com/en-us/library/dd358575.aspx

        :param operation: A string representing sql statement.
        """
        #logger.debug('submit_plain_query(%s)', operation)
        self.messages = []
        self.cancel_if_pending()
        self.res_info = None
        w = self._writer
        with self.querying_context(TDS_QUERY):
            self._START_QUERY()
            w.write_ucs2(operation)

    def submit_bulk(self, metadata, rows):
        """ Sends insert bulk command.

        Spec: http://msdn.microsoft.com/en-us/library/dd358082.aspx

        :param metadata: A list of :class:`Column` instances.
        :param rows: A collection of rows, each row is a collection of values.
        :return:
        """
        num_cols = len(metadata)
        w = self._writer
        with self.querying_context(TDS_BULK):
            w.put_byte(TDS7_RESULT_TOKEN)
            w.put_usmallint(num_cols)
            for col in metadata:
                if IS_TDS72_PLUS(self):
                    w.put_uint(col.column_usertype)
                else:
                    w.put_usmallint(col.column_usertype)
                w.put_usmallint(col.flags)
                w.put_byte(col.type.type)
                col.type.write_info(w)
                w.put_byte(len(col.column_name))
                w.write_ucs2(col.column_name)
            for row in rows:
                w.put_byte(TDS_ROW_TOKEN)
                for i, col in enumerate(metadata):
                    col.type.write(w, row[i])

            w.put_byte(TDS_DONE_TOKEN)
            w.put_usmallint(TDS_DONE_FINAL)
            w.put_usmallint(0)  # curcmd
            if IS_TDS72_PLUS(self):
                w.put_int8(0)
            else:
                w.put_int(0)

    def _put_cancel(self):
        """ Sends a cancel request to the server.

        Switches connection to IN_CANCEL state.
        """
        self._writer.begin_packet(TDS_CANCEL)
        self._writer.flush()
        self.in_cancel = 1

    _begin_tran_struct_72 = struct.Struct('<HBB')

    def begin_tran(self, isolation_level=0):
        self.submit_begin_tran(isolation_level=isolation_level)
        self.process_simple_request()

    def submit_begin_tran(self, isolation_level=0):
        #logger.debug('submit_begin_tran()')
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(TDS7_TRANS):
                self._start_query()
                w.pack(self._begin_tran_struct_72,
                    5,  # TM_BEGIN_XACT
                    isolation_level,
                    0,  # new transaction name
                    )
        else:
            self.submit_plain_query("BEGIN TRANSACTION")
            self.conn.tds72_transaction = 1

    _commit_rollback_tran_struct72_hdr = struct.Struct('<HBB')
    _continue_tran_struct72 = struct.Struct('<BB')

    def rollback(self, cont, isolation_level=0):
        self.submit_rollback(cont, isolation_level=isolation_level)
        prev_timeout = self._tds._sock.gettimeout()
        self._tds._sock.settimeout(None)
        try:
            self.process_simple_request()
        finally:
            self._tds._sock.settimeout(prev_timeout)

    def submit_rollback(self, cont, isolation_level=0):
        #logger.debug('submit_rollback(%s, %s)', id(self), cont)
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(TDS7_TRANS):
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
        else:
            self.submit_plain_query("IF @@TRANCOUNT > 0 ROLLBACK BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 ROLLBACK")
            self.conn.tds72_transaction = 1 if cont else 0

    def commit(self, cont, isolation_level=0):
        self.submit_commit(cont, isolation_level=isolation_level)
        prev_timeout = self._tds._sock.gettimeout()
        self._tds._sock.settimeout(None)
        try:
            self.process_simple_request()
        finally:
            self._tds._sock.settimeout(prev_timeout)

    def submit_commit(self, cont, isolation_level=0):
        #logger.debug('submit_commit(%s)', cont)
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.querying_context(TDS7_TRANS):
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
        else:
            self.submit_plain_query("IF @@TRANCOUNT > 0 COMMIT BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 COMMIT")
            self.conn.tds72_transaction = 1 if cont else 0

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

    def _send_prelogin(self, login):
        instance_name = login.instance_name or 'MSSQLServer'
        instance_name = instance_name.encode('ascii')
        encryption_level = login.encryption_level
        if len(instance_name) > 65490:
            raise ValueError('Instance name is too long')
        if encryption_level >= TDS_ENCRYPTION_REQUIRE:
            raise NotSupportedError('Client requested encryption but it is not supported')
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
        from . import intversion
        w.put_uint_be(intversion)
        w.put_usmallint_be(0)  # build number
        # encryption
        if ENCRYPTION_ENABLED and encryption_supported:
            w.put_byte(1 if encryption_level >= TDS_ENCRYPTION_REQUIRE else 0)
        else:
            # not supported
            w.put_byte(2)
        w.write(instance_name)
        w.put_byte(0)  # zero terminate instance_name
        w.put_int(0)  # TODO: change this to thread id
        if IS_TDS72_PLUS(self):
            # MARS (1 enabled)
            w.put_byte(1 if login.use_mars else 0)
        w.flush()

    def _process_prelogin(self, login):
        p = self._reader.read_whole_packet()
        size = len(p)
        if size <= 0 or self._reader.packet_type != 4:
            self.bad_stream('Invalid packet type: {0}, expected PRELOGIN(4)'.format(self._reader.packet_type))
        # default 2, no certificate, no encryptption
        crypt_flag = 2
        i = 0
        byte_struct = struct.Struct('B')
        off_len_struct = struct.Struct('>HH')
        prod_version_struct = struct.Struct('>LH')
        while True:
            if i >= size:
                self.bad_stream('Invalid size of PRELOGIN structure')
            type, = byte_struct.unpack_from(p, i)
            if type == 0xff:
                break
            if i + 4 > size:
                self.bad_stream('Invalid size of PRELOGIN structure')
            off, l = off_len_struct.unpack_from(p, i + 1)
            if off > size or off + l > size:
                self.bad_stream('Invalid offset in PRELOGIN structure')
            if type == self.VERSION:
                self.conn.server_library_version = prod_version_struct.unpack_from(p, off)
            elif type == self.ENCRYPTION and l >= 1:
                crypt_flag, = byte_struct.unpack_from(p, off)
            elif type == self.MARS:
                self.conn._mars_enabled = bool(byte_struct.unpack_from(p, off)[0])
            elif type == self.INSTOPT:
                # ignore instance name mismatch
                pass
            i += 5
        # if server do not has certificate do normal login
        if crypt_flag == 2:
            if login.encryption_level >= TDS_ENCRYPTION_REQUIRE:
                raise Error('Server required encryption but it is not supported')
            return
        self._sock = ssl.wrap_socket(self._sock, ssl_version=ssl.PROTOCOL_SSLv3)

    def tds7_send_login(self, login):
        option_flag2 = login.option_flag2
        user_name = login.user_name
        if len(user_name) > 128:
            raise ValueError('User name should be no longer that 128 characters')
        if len(login.password) > 128:
            raise ValueError('Password should be not longer than 128 characters')
        if len(login.change_password) > 128:
            raise ValueError('Password should be not longer than 128 characters')
        if len(login.client_host_name) > 128:
            raise ValueError('Host name should be not longer than 128 characters')
        if len(login.app_name) > 128:
            raise ValueError('App name should be not longer than 128 characters')
        if len(login.server_name) > 128:
            raise ValueError('Server name should be not longer than 128 characters')
        if len(login.database) > 128:
            raise ValueError('Database name should be not longer than 128 characters')
        if len(login.language) > 128:
            raise ValueError('Language should be not longer than 128 characters')
        if len(login.attach_db_file) > 260:
            raise ValueError('File path should be not longer than 260 characters')
        w = self._writer
        w.begin_packet(TDS7_LOGIN)
        self.authentication = None
        current_pos = 86 + 8 if IS_TDS72_PLUS(self) else 86
        client_host_name = login.client_host_name
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
        from . import intversion
        w.put_uint(intversion)
        w.put_int(login.pid)
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
        mins_fix = int(total_seconds(login.client_tz.utcoffset(datetime.now()))) // 60
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
        client_id = struct.pack('>Q', login.client_id)[2:]
        w.write(client_id)
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
            w.put_smallint(len(login.change_password))
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
        w.write_ucs2(login.change_password)
        w.flush()

    _SERVER_TO_CLIENT_MAPPING = {
        0x07000000: TDS70,
        0x07010000: TDS71,
        0x71000001: TDS71rev1,
        TDS72: TDS72,
        TDS73A: TDS73A,
        TDS73B: TDS73B,
        TDS74: TDS74,
        }

    def process_login_tokens(self):
        r = self._reader
        succeed = False
        #logger.debug('process_login_tokens()')
        while True:
            marker = r.get_byte()
            #logger.debug('looking for login token, got  {0:x}({1})'.format(marker, tds_token_name(marker)))
            if marker == TDS_LOGINACK_TOKEN:
                succeed = True
                size = r.get_smallint()
                r.get_byte()  # interface
                version = r.get_uint_be()
                self.conn.tds_version = self._SERVER_TO_CLIENT_MAPPING.get(version, version)
                #logger.debug('server reports TDS version {0:x}'.format(version))
                if not IS_TDS7_PLUS(self):
                    self.bad_stream('Only TDS 7.0 and higher are supported')
                # get server product name
                # ignore product name length, some servers seem to set it incorrectly
                r.get_byte()
                size -= 10
                self.conn.product_name = r.read_ucs2(size // 2)
                product_version = r.get_uint_be()
                # MSSQL 6.5 and 7.0 seem to return strange values for this
                # using TDS 4.2, something like 5F 06 32 FF for 6.50
                self.conn.product_version = product_version
                #logger.debug('Product version {0:x}'.format(product_version))
                if self.conn.authentication:
                    self.conn.authentication.close()
                    self.conn.authentication = None
            else:
                self.process_token(marker)
                if marker == TDS_DONE_TOKEN:
                    break
        return succeed

    def process_returnstatus(self):
        self.ret_status = self._reader.get_int()
        self.has_status = True

    def process_token(self, marker):
        handler = _token_map.get(marker)
        if not handler:
            self.bad_stream('Invalid TDS marker: {0}({0:x})'.format(marker))
        return handler(self)

    def get_token_id(self):
        self.set_state(TDS_READING)
        try:
            marker = self._reader.get_byte()
        except TimeoutError:
            self.set_state(TDS_PENDING)
            raise
        except:
            self._tds.close()
            raise
        return marker

    def process_simple_request(self):
        while True:
            marker = self.get_token_id()
            if marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & TDS_DONE_MORE_RESULTS:
                    # skip results that don't event have rowcount
                    continue
                return
            else:
                self.process_token(marker)

    def next_set(self):
        while self.more_rows:
            self.next_row()
        if self.state == TDS_IDLE:
            return False
        if self.find_result_or_done():
            return True

    def fetchone(self):
        if self.res_info is None:
            raise Error("Previous statement didn't produce any results")

        if self.skipped_to_status:
            raise Error("Unable to fetch any rows after accessing return_status")

        if not self.next_row():
            return None

        return self.row

    def next_row(self):
        if not self.more_rows:
            return False
        while True:
            marker = self.get_token_id()
            if marker in (TDS_ROW_TOKEN, TDS_NBC_ROW_TOKEN):
                self.process_token(marker)
                return True
            elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                return False
            else:
                self.process_token(marker)

    def find_result_or_done(self):
        self.done_flags = 0
        while True:
            marker = self.get_token_id()
            if marker == TDS7_RESULT_TOKEN:
                self.process_token(marker)
                return True
            elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & TDS_DONE_MORE_RESULTS:
                    if self.done_flags & TDS_DONE_COUNT:
                        return True
                    else:
                        # skip results without rowcount
                        continue
                else:
                    return False
            else:
                self.process_token(marker)

    def process_rpc(self):
        self.done_flags = 0
        self.return_value_index = 0
        while True:
            marker = self.get_token_id()
            if marker == TDS7_RESULT_TOKEN:
                self.process_token(marker)
                return True
            elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN):
                self.process_end(marker)
                if self.done_flags & TDS_DONE_MORE_RESULTS and not self.done_flags & TDS_DONE_COUNT:
                    # skip results that don't event have rowcount
                    continue
                return False
            else:
                self.process_token(marker)

    def find_return_status(self):
        self.skipped_to_status = True
        while True:
            marker = self.get_token_id()
            self.process_token(marker)
            if marker == TDS_RETURNSTATUS_TOKEN:
                return


_token_map = {
    TDS_AUTH_TOKEN: _TdsSession.process_auth,
    TDS_ENVCHANGE_TOKEN: _TdsSession.process_env_chg,
    TDS_DONE_TOKEN: lambda self: self.process_end(TDS_DONE_TOKEN),
    TDS_DONEPROC_TOKEN: lambda self: self.process_end(TDS_DONEPROC_TOKEN),
    TDS_DONEINPROC_TOKEN: lambda self: self.process_end(TDS_DONEINPROC_TOKEN),
    TDS_ERROR_TOKEN: lambda self: self.process_msg(TDS_ERROR_TOKEN),
    TDS_INFO_TOKEN: lambda self: self.process_msg(TDS_INFO_TOKEN),
    TDS_EED_TOKEN: lambda self: self.process_msg(TDS_EED_TOKEN),
    TDS_CAPABILITY_TOKEN: lambda self: self.process_msg(TDS_CAPABILITY_TOKEN),
    TDS_PARAM_TOKEN: lambda self: self.process_param(),
    TDS7_RESULT_TOKEN: lambda self: self.tds7_process_result(),
    TDS_ROW_TOKEN: lambda self: self.process_row(),
    TDS_NBC_ROW_TOKEN: lambda self: self.process_nbcrow(),
    TDS_ORDERBY2_TOKEN: lambda self: self.process_orderby2(),
    TDS_ORDERBY_TOKEN: lambda self: self.process_orderby(),
    TDS_RETURNSTATUS_TOKEN: lambda self: self.process_returnstatus(),
    }


class _TdsSocket(object):
    def __init__(self, use_tz=None):
        self._is_connected = False
        self.env = _TdsEnv()
        self.collation = None
        self.tds72_transaction = 0
        self.authentication = None
        self._mars_enabled = False
        self.chunk_handler = MemoryChunkedHandler()
        self._sock = None
        self._bufsize = 4096
        self.tds_version = TDS74
        self.use_tz = use_tz

    def __repr__(self):
        fmt = "<_TdsSocket tran={} mars={} tds_version={} use_tz={}>"
        return fmt.format(self.tds72_transaction, self._mars_enabled,
                          self.tds_version, self.use_tz)

    def login(self, login, sock, tzinfo_factory):
        self.login = login
        self._bufsize = login.blocksize
        self.query_timeout = login.query_timeout
        self._main_session = _TdsSession(self, self, tzinfo_factory)
        self._sock = sock
        self.tds_version = login.tds_version
        if IS_TDS71_PLUS(self):
            self._main_session._send_prelogin(login)
            self._main_session._process_prelogin(login)
        if IS_TDS7_PLUS(self):
            self._main_session.tds7_send_login(login)
        else:
            raise ValueError('This TDS version is not supported')
        if not self._main_session.process_login_tokens():
            self._main_session.raise_db_exception()
        if IS_TDS72_PLUS(self):
            self._type_map = _type_map72
        elif IS_TDS71_PLUS(self):
            self._type_map = _type_map71
        else:
            self._type_map = _type_map
        text_size = login.text_size
        if self._mars_enabled:
            from .smp import SmpManager
            self._smp_manager = SmpManager(self)
            self._main_session = _TdsSession(
                self,
                self._smp_manager.create_session(),
                tzinfo_factory)
        self._is_connected = True
        q = []
        if text_size:
            q.append('set textsize {0}'.format(int(text_size)))
        if login.database and self.env.database != login.database:
            q.append('use ' + tds_quote_id(login.database))
        if q:
            self._main_session.submit_plain_query(''.join(q))
            self._main_session.process_simple_request()

    @property
    def mars_enabled(self):
        return self._mars_enabled

    @property
    def main_session(self):
        return self._main_session

    def create_session(self, tzinfo_factory):
        return _TdsSession(
            self, self._smp_manager.create_session(),
            tzinfo_factory)

    def read(self, size):
        buf = self._sock.recv(size)
        if len(buf) == 0:
            self.close()
            raise ClosedConnectionError()
        return buf

    def _write(self, data, final):
        try:
            flags = 0
            if hasattr(socket, 'MSG_NOSIGNAL'):
                flags |= socket.MSG_NOSIGNAL
            if not final:
                if hasattr(socket, 'MSG_MORE'):
                    flags |= socket.MSG_MORE
            self._sock.sendall(data, flags)
            if final and USE_CORK:
                self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 0)
                self._sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 1)
        except:
            self.close()
            raise

    send = _write

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

    def NVarChar(self, size, collation=raw_collation):
        if IS_TDS72_PLUS(self):
            return NVarChar72(size, collation)
        elif IS_TDS71_PLUS(self):
            return NVarChar71(size, collation)
        else:
            return NVarChar70(size)

    def VarChar(self, size, collation=raw_collation):
        if IS_TDS72_PLUS(self):
            return VarChar72(size, collation)
        elif IS_TDS71_PLUS(self):
            return VarChar71(size, collation)
        else:
            return VarChar70(size, codec=self.server_codec)

    def Text(self, size=0, collation=raw_collation):
        if IS_TDS72_PLUS(self):
            return Text72(size, collation=collation)
        elif IS_TDS71_PLUS(self):
            return Text71(size, collation=collation)
        else:
            return Text70(size, codec=self.server_codec)

    def NText(self, size=0, collation=raw_collation):
        if IS_TDS72_PLUS(self):
            return NText72(size, collation=collation)
        elif IS_TDS71_PLUS(self):
            return NText71(size, collation=collation)
        else:
            return NText70(size)

    def VarBinary(self, size):
        if IS_TDS72_PLUS(self):
            return VarBinary72(size)
        else:
            return VarBinary(size)

    def Image(self, size=0):
        if IS_TDS72_PLUS(self):
            return Image72(size)
        else:
            return Image70(size)

    Bit = Bit.instance
    BitN = BitN.instance
    TinyInt = TinyInt.instance
    SmallInt = SmallInt.instance
    Int = Int.instance
    BigInt = BigInt.instance
    IntN = IntN
    Real = Real.instance
    Float = Float.instance
    FloatN = FloatN
    SmallDateTime = SmallDateTime.instance
    DateTime = DateTime.instance
    DateTimeN = DateTimeN
    Date = MsDate.instance
    Time = MsTime
    DateTime2 = DateTime2
    DateTimeOffset = DateTimeOffset
    Decimal = MsDecimal
    SmallMoney = Money4.instance
    Money = Money8.instance
    MoneyN = MoneyN
    UniqueIdentifier = MsUnique.instance
    SqlVariant = Variant
    Xml = Xml

    def long_binary_type(self):
        if IS_TDS72_PLUS(self):
            return VarBinaryMax()
        else:
            return Image70()

    def long_varchar_type(self, collation=raw_collation):
        if IS_TDS72_PLUS(self):
            return VarCharMax(collation)
        elif IS_TDS71_PLUS(self):
            return Text71(-1, '', collation)
        else:
            return Text70(codec=self.server_codec)

    def long_string_type(self, collation=raw_collation):
        if IS_TDS72_PLUS(self):
            return NVarCharMax(0, collation)
        elif IS_TDS71_PLUS(self):
            return NText71(-1, '', collation)
        else:
            return NText70()

    def type_by_declaration(self, declaration, nullable):
        declaration = declaration.strip().upper()
        for type_class in self._type_map.values():
            type_inst = type_class.from_declaration(declaration, nullable, self)
            if type_inst:
                return type_inst 
        raise ValueError('Unable to parse type declaration', declaration)


class Column(object):
    fNullable = 1
    fCaseSen = 2
    fReadWrite = 8
    fIdentity = 0x10
    fComputed = 0x20

    def __init__(self, name='', type=None, flags=0, value=None):
        self.char_codec = None
        self.column_name = name
        self.column_usertype = 0
        self.flags = flags
        self.type = type
        self.value = value

    def __repr__(self):
        return '<Column(name={0}, value={1}, type={2})>'.format(repr(self.column_name), repr(self.value), repr(self.type))


class _Results(object):
    def __init__(self):
        self.columns = []
        self.row_count = 0


def _parse_instances(msg):
    name = None
    if len(msg) > 3 and _ord(msg[0]) == 5:
        tokens = msg[3:].decode('ascii').split(';')
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
                    results[instdict['InstanceName'].upper()] = instdict
                    instdict = {}
                    continue
                got_name = True
        return results


#
# Get port of all instances
# @return default port number or 0 if error
# @remark experimental, cf. MC-SQLR.pdf.
#
def tds7_get_instances(ip_addr, timeout=5):
    s = socket.socket(type=socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # send the request
        s.sendto(b'\x03', (ip_addr, 1434))
        msg = s.recv(16 * 1024 - 1)
        # got data, read and parse
        return _parse_instances(msg)
    finally:
        s.close()


def _applytz(dt, tz):
    if not tz:
        return dt
    dt = dt.replace(tzinfo=tz)
    return dt
