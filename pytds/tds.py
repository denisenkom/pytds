import struct
import codecs
import logging
import socket
import sys
from datetime import datetime, date, time, timedelta
from decimal import Decimal, localcontext
from dateutil.tz import tzoffset, tzutc
import uuid
import six
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
BINNTYPE = SYBBITN = 104  # 0x68
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

_utc = tzutc()

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
    return '[{0}]'.format(id.replace(']', ']]'))


def tds7_crypt_pass(password):
    encoded = bytearray(ucs2_codec.encode(password)[0])
    for i, ch in enumerate(encoded):
        encoded[i] = ((ch << 4) & 0xff | (ch >> 4)) ^ 0xA5
    return encoded


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

    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + val, reversed(buf), 0)
else:
    exc_base_class = StandardError

    def _ord(val):
        return ord(val)

    def _decode_num(buf):
        return reduce(lambda acc, val: acc * 256 + ord(val), reversed(buf), 0)


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


def readall(stm, size):
    res = stm.read(size)
    if len(res) == size:
        return res
    elif len(res) == 0:
        raise ClosedConnectionError()
    chunks = [res]
    left = size - len(res)
    while left:
        buf = stm.read(left)
        if len(buf) == 0:
            raise ClosedConnectionError()
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

    def get_smallint(self):
        return self.unpack(_smallint_le)[0]

    def get_usmallint(self):
        return self.unpack(_usmallint_le)[0]

    def get_int(self):
        return self.unpack(_int_le)[0]

    def get_uint(self):
        return self.unpack(_uint_le)[0]

    def get_uint_be(self):
        return self.unpack(_uint_be)[0]

    def get_uint8(self):
        return self.unpack(_uint8_le)[0]

    def get_int8(self):
        return self.unpack(_int8_le)[0]

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
    def __init__(self, session, bufsize):
        self._session = session
        self._tds = session
        self._transport = session
        self._pos = 0
        self._buf = bytearray(bufsize)
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

    def put_smallint(self, value):
        self.pack(_smallint_le, value)

    def put_usmallint(self, value):
        self.pack(_usmallint_le, value)

    def put_smallint_be(self, value):
        self.pack(_smallint_be, value)

    def put_usmallint_be(self, value):
        self.pack(_usmallint_be, value)

    def put_int(self, value):
        self.pack(_int_le, value)

    def put_uint(self, value):
        self.pack(_uint_le, value)

    def put_int_be(self, value):
        self.pack(_int_be, value)

    def put_uint_be(self, value):
        self.pack(_uint_be, value)

    def put_int8(self, value):
        self.pack(_int8_le, value)

    def put_uint8(self, value):
        self.pack(_uint8_le, value)

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
        pass

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

BitN.instance = BitN()


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
        1: struct.Struct('B'),
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

    @classmethod
    def from_stream(cls, r):
        return cls()

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

    @classmethod
    def from_stream(cls, r):
        return cls()

    def get_declaration(self):
        return 'FLOAT'

    def write_info(self, w):
        pass

    def write(self, w, val):
        w.pack(_flt8_struct, val)

    def read(self, r):
        return r.unpack(_flt8_struct)[0]
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
            w.put_byte(0)
        else:
            w.put_byte(self._size)
            self._subtype[self._size].write(w, val)

    def read(self, r):
        size = r.get_byte()
        if not size:
            return None
        else:
            if size == 8:
                return r.unpack(_flt8_struct)[0]
            elif size == 4:
                return r.unpack(_flt4_struct)[0]
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
        return r.read_str(size, r.session.conn.server_codec)


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

    def read(self, r):
        size = r.get_smallint()
        if size < 0:
            return None
        return r.read_str(size, self._codec)


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

    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        return cls(size)

    def get_declaration(self):
        return 'NVARCHAR({})'.format(self._size)

    def write_info(self, w):
        w.put_usmallint(self._size * 2)
        #w.put_smallint(self._size)

    def write(self, w, val):
        if val is None:
            w.put_usmallint(0xffff)
        else:
            if isinstance(val, bytes):
                val = val.decode('utf8')
            w.put_usmallint(len(val) * 2)
            #w.put_smallint(len(val))
            w.write_ucs2(val)

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
        return cls(size, collation)

    def write_info(self, w):
        super(NVarChar71, self).write_info(w)
        w.put_collation(self._collation)


class NVarChar72(NVarChar71):
    def __init__(self, size, collation=raw_collation):
        super(NVarChar72, self).__init__(size, collation)
        if size == 0xffff:
            self.read = self._read_max
            self.write = self._write_max
            self.write_info = self._write_info_max

    @classmethod
    def from_stream(cls, r):
        size = r.get_usmallint()
        collation = r.get_collation()
        return cls(size, collation)

    def get_declaration(self):
        if self._size == 0xffff:
            return 'NVARCHAR(MAX)'
        else:
            return super(NVarChar72, self).get_declaration()

    def _write_info_max(self, w):
        w.put_usmallint(0xffff)
        w.put_collation(self._collation)

    def _write_max(self, w, val):
        if val is None:
            w.put_uint8(0xffffffffffffffff)
        else:
            if isinstance(val, bytes):
                val = val.decode('utf8')
            w.put_uint8(len(val) * 2)
            w.put_uint(len(val) * 2)
            w.write_ucs2(val)
            w.put_uint(0)

    def _read_max(self, r):
        size = r.get_uint8()
        if size == 0xffffffffffffffff:
            return None
        chunks = []
        decoder = ucs2_codec.incrementaldecoder()
        while True:
            chunk_len = r.get_uint()
            if chunk_len <= 0:
                chunks.append(decoder.decode(b'', True))
                res = ''.join(chunks)
                return res
            left = chunk_len
            while left:
                buf = r.read(left)
                chunk = decoder.decode(buf)
                left -= len(buf)
                chunks.append(chunk)


class Xml(NVarChar72):
    type = SYBMSXML

    def __init__(self, schema={}):
        super(Xml, self).__init__(0xffff)
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


class Text(BaseType):
    type = SYBTEXT

    def __init__(self, size, table_name):
        self._size = size
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        readall(r, size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, r.session.conn.server_codec)


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
        if size == 0:
            return None
        readall(r, size)  # textptr
        readall(r, 8)  # timestamp
        colsize = r.get_int()
        return r.read_str(colsize, self._codec)


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

    def __init__(self, size=100, table_name=''):
        self._size = size
        self._table_name = table_name

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        table_name = r.read_ucs2(r.get_smallint())
        return cls(size, table_name)

    def get_declaration(self):
        return 'NTEXT'

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
            w.put_int(0)
        else:
            w.put_int(len(val) * 2)
            w.write_ucs2(val)


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
        size = r.get_usmallint()
        return cls(size)

    def get_declaration(self):
        return 'VARBINARY({})'.format(self._size)

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
    def __init__(self, size):
        self._size = size
        if size == 0xffff:
            self.read = self._read_max
            self.write = self._write_max
            self.write_info = self._write_info_max
            self.get_declaration = self._get_declaration_max

    def _get_declaration_max(self):
        return 'VARBINARY(MAX)'

    def _write_info_max(self, w):
        w.put_usmallint(0xffff)

    def _write_max(self, w, val):
        if val is None:
            w.put_uint8(0xffffffffffffffff)
        else:
            w.put_uint8(len(val))
            if val:
                w.put_uint(len(val))
                w.write(val)
            w.put_uint(0)

    def _read_max(self, r):
        size = r.get_uint8()
        if size == 0xffffffffffffffff:
            return None
        chunks = []
        while True:
            chunk_len = r.get_uint()
            if chunk_len == 0:
                return b''.join(chunks)
            left = chunk_len
            while left:
                chunk = r.read(left)
                left -= len(chunk)
                chunks.append(chunk)


class Image(BaseType):
    type = SYBIMAGE

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

    def write(self, w, val):
        if val is None:
            w.put_byte(0)
            return


class Image72(Image):
    def __init__(self, size, parts):
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

    def write_info(self, w):
        w.put_int(self._size)
        w.put_byte(len(self._parts))
        for part in self._parts:
            w.put_usmallint(len(part))
            w.write_ucs2(part)


class BaseDateTime(BaseType):
    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)


class SmallDateTime(BaseDateTime):
    type = SYBDATETIME4

    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(2079, 6, 6, 23, 59, 0)
    _struct = struct.Struct('<HH')

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def get_declaration(self):
        return 'SMALLDATETIME'

    def write_info(self, w):
        pass

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
        return (self._base_date + timedelta(days=days, minutes=minutes)).replace(tzinfo=r.session.use_tz)
SmallDateTime.instance = SmallDateTime()


class DateTime(BaseDateTime):
    type = SYBDATETIME

    _struct = struct.Struct('<ll')

    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def get_declaration(self):
        return 'DATETIME'

    def write_info(self, w):
        pass

    def write(self, w, val):
        if val.tzinfo:
            if not w.session.use_tz:
                raise DataError('Timezone-aware datetime is used without specifying use_tz')
            val = val.astimezone(w.session.use_tz).replace(tzinfo=None)
        w.write(self.encode(val))

    def read(self, r):
        days, t = r.unpack(self._struct)
        return _applytz(self.decode(days, t), r.session.use_tz)

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


class DateTimeN(BaseType):
    type = SYBDATETIMN

    _base_date = datetime(1900, 1, 1)
    _min_date = datetime(1753, 1, 1, 0, 0, 0)
    _max_date = datetime(9999, 12, 31, 23, 59, 59, 997000)

    def __init__(self, size):
        assert size in (4, 8)
        self._size = size
        self._subtype = {4: SmallDateTime.instance, 8: DateTime.instance}[size]

    @classmethod
    def from_stream(self, r):
        size = r.get_byte()
        if size not in (4, 8):
            raise InterfaceError('Invalid SYBDATETIMN size', size)
        return DateTimeN(size)

    def get_declaration(self):
        return self._subtype.get_declaration()

    def write_info(self, w):
        w.put_byte(self._size)

    def write(self, w, val):
        if val is None:
            w.put_byte(0)
        else:
            w.put_byte(self._size)
            self._subtype.write(w, val)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size != self._size:
            r.bad_stream('Received an invalid column length from server')
        return self._subtype.read(r)


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

    MIN = date(1, 1, 1)
    MAX = date(9999, 12, 31)

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


class Money4(BaseType):
    type = SYBMONEY4

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def write_info(self, w):
        pass

    def get_declaration(self):
        return 'SMALLMONEY'

    def read(self, r):
        return Decimal(r.get_int()) / 10000

    def write(self, w, val):
        val = int(val * 10000)
        w.put_int(val)

Money4.instance = Money4()


class Money8(BaseType):
    type = SYBMONEY
    _struct = struct.Struct('<lL')

    @classmethod
    def from_stream(cls, r):
        return cls.instance

    def write_info(self, w):
        pass

    def get_declaration(self):
        return 'MONEY'

    def get_typeid(self):
        return self.type

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


class MoneyN(BaseType):
    type = SYBMONEYN
    _subtypes = {
        4: Money4.instance,
        8: Money8.instance,
        }

    def __init__(self, size):
        assert size in self._subtypes.keys()
        self._size = size
        self._typeid = self._subtypes[size].type
        self._subtype = self._subtypes[size]

    def get_typeid(self):
        return self._typeid

    def get_declaration(self):
        return self._subtype.get_declaration()

    @classmethod
    def from_stream(cls, r):
        size = r.get_byte()
        if size not in cls._subtypes.keys():
            raise InterfaceError('Invalid SYBMONEYN size', size)
        return cls(size)

    def write_info(self, w):
        w.put_byte(self._size)

    def read(self, r):
        size = r.get_byte()
        if size == 0:
            return None
        if size != self._size:
            raise r.session.bad_stream('Invalid SYBMONEYN size', size)
        return self._subtype.read(r)

    def write(self, w, val):
        if val is None:
            w.put_byte(0)
            return
        w.put_byte(self._size)
        self._subtype.write(w, val)


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
        return 'SQL_VARIANT'

    @classmethod
    def from_stream(cls, r):
        size = r.get_int()
        return Variant(size)

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


class _TdsSession(object):
    def __init__(self, tds, transport):
        self.out_pos = 8
        self.res_info = None
        self.in_cancel = False
        self.wire_mtx = None
        self.param_info = None
        self.has_status = False
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

    def raise_db_exception(self):
        if not self.messages:
            raise Error("Request failed, server didn't send error message")
        while True:
            msg = self.messages[-1]
            if msg['msgno'] == 3621:  # the statement has been terminated
                self.messages = self.messages[:-1]
            else:
                break

        msg_no = msg['msgno']
        error_msg = ' '.join(msg['message'] for msg in self.messages)
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
        self.messages = []
        raise ex

    def get_type_factory(self, type_id):
        factory = self._tds._type_map.get(type_id)
        if not factory:
            raise InterfaceError('Invalid type id', type_id)
        return factory

    def get_type_info(self, curcol):
        r = self._reader
        # User defined data type of the column
        curcol.column_usertype = r.get_uint() if IS_TDS72_PLUS(self) else r.get_usmallint()
        curcol.flags = r.get_usmallint()  # Flags
        curcol.column_nullable = curcol.flags & Column.fNullable
        curcol.column_writeable = (curcol.flags & Column.fReadWrite) > 0
        curcol.column_identity = (curcol.flags & Column.fIdentity) > 0
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
            return

        self.param_info = None
        self.has_status = False
        self.ret_status = False
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
            header_tuple.append((curcol.column_name, curcol.type.get_typeid(), None, None, precision, scale, curcol.column_nullable))
        info.description = tuple(header_tuple)
        return info

    def process_param(self):
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
        '''
        Process the incoming token stream until it finds
        an end token DONE with the cancel flag set.
        At that point the connection should be ready to handle a new query.
        '''
        # silly cases, nothing to do
        if not self.in_cancel:
            return

        # TODO support TDS5 cancel, wait for cancel packet first, then wait for done
        while True:
            token_id = self.get_token_id()
            self.process_token(token_id)
            if not self.in_cancel:
                return

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
                    self.process_token(next_marker)
                else:
                    break
            r.unget_byte()

        # special case
        self.messages.append(msg)

    def process_row(self):
        r = self._reader
        info = self.res_info
        info.row_count += 1
        for i, curcol in enumerate(info.columns):
            curcol.value = self.row[i] = curcol.type.read(r)

    # NBC=null bitmap compression row
    # http://msdn.microsoft.com/en-us/library/dd304783(v=prot.20).aspx
    def process_nbcrow(self):
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
        r = self._reader
        skipall(r, r.get_smallint())

    def process_orderby2(self):
        r = self._reader
        skipall(r, r.get_int())

    def process_end(self, marker):
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
            #tds_srv_charset_changed(self, newval)
        elif type == TDS_ENV_DB_MIRRORING_PARTNER:
            r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
        elif type == TDS_ENV_LCID:
            lcid = int(r.read_ucs2(r.get_byte()))
            self.conn.server_codec = codecs.lookup(lcid2charset(lcid))
            r.read_ucs2(r.get_byte())
        else:
            logger.warning("unknown env type: {}, skipping".format(type))
            # discard byte values, not still supported
            skipall(r, size - 1)

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

    def is_connected(self):
        return self._transport.is_connected()

    def bad_stream(self, msg):
        self.close()
        raise InterfaceError(msg)

    @property
    def tds_version(self):
        return self._tds.tds_version

    @property
    def conn(self):
        return self._tds

    def close(self):
        self._transport.close()

    def set_state(self, state):
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

    def state_context(self, state):
        return _StateContext(self, state)

    def query_flush_packet(self):
        # TODO depend on result ??
        self.set_state(TDS_PENDING)
        self._writer.flush()

    def make_param(self, name, value):
        if isinstance(value, Column):
            value.column_name = name
            return value
        column = Column()
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
            if size == 0:
                size = 1
            if size > 8000:
                if IS_TDS72_PLUS(self):
                    column.type = VarBinary72(0xffff)
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
                    column.type = NVarChar72(0xffff, self.conn.collation)
                elif IS_TDS71_PLUS(self):
                    column.type = NText71(-1, '', self.conn.collation)
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
                column.type = DateTimeN(8)
        elif isinstance(value, date):
            if IS_TDS73_PLUS(self):
                column.type = MsDate()
            else:
                column.type = DateTimeN(8)
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
                params.append(self.make_param('', parameter))
            return params

    def cancel_if_pending(self):
        if self.state == TDS_IDLE:
            return
        if not self.in_cancel:
            self._put_cancel()
        self.process_cancel()

    def submit_rpc(self, rpc_name, params, flags):
        self.messages = []
        self.output_params = {}
        self.cancel_if_pending()
        self.res_info = None
        w = self._writer
        with self.state_context(TDS_QUERYING):
            w.begin_packet(TDS_RPC)
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
            self.query_flush_packet()

    def submit_plain_query(self, operation):
        #logger.debug('submit_plain_query(%s)', operation)
        self.messages = []
        self.cancel_if_pending()
        self.res_info = None
        w = self._writer
        with self.state_context(TDS_QUERYING):
            w.begin_packet(TDS_QUERY)
            self._START_QUERY()
            w.write_ucs2(operation)
            self.query_flush_packet()

    def submit_bulk(self, metadata, rows):
        num_cols = len(metadata)
        w = self._writer
        with self.state_context(TDS_QUERYING):
            w.begin_packet(TDS_BULK)
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
            self.query_flush_packet()


    def _put_cancel(self):
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
            with self.state_context(TDS_QUERYING):
                w.begin_packet(TDS7_TRANS)
                self._start_query()
                w.pack(self._begin_tran_struct_72,
                    5,  # TM_BEGIN_XACT
                    isolation_level,
                    0,  # new transaction name
                    )
                self.query_flush_packet()
        else:
            self.submit_plain_query("BEGIN TRANSACTION")

    _commit_rollback_tran_struct72_hdr = struct.Struct('<HBB')
    _continue_tran_struct72 = struct.Struct('<BB')

    def rollback(self, cont, isolation_level=0):
        self.submit_rollback(cont, isolation_level=isolation_level)
        self.process_simple_request()

    def submit_rollback(self, cont, isolation_level=0):
        #logger.debug('submit_rollback(%s, %s)', id(self), cont)
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.state_context(TDS_QUERYING):
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
            self.submit_plain_query("IF @@TRANCOUNT > 0 ROLLBACK BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 ROLLBACK")

    def commit(self, cont, isolation_level=0):
        self.submit_commit(cont, isolation_level=isolation_level)
        self.process_simple_request()

    def submit_commit(self, cont, isolation_level=0):
        #logger.debug('submit_commit(%s)', cont)
        if IS_TDS72_PLUS(self):
            self.messages = []
            self.cancel_if_pending()
            w = self._writer
            with self.state_context(TDS_QUERYING):
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
            self.submit_plain_query("IF @@TRANCOUNT > 0 COMMIT BEGIN TRANSACTION" if cont else "IF @@TRANCOUNT > 0 COMMIT")

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
        from pytds import intversion
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
            self.bad_stream('Invalid packet type: {}, expected PRELOGIN(4)'.format(self._reader.packet_type))
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
                instopt = byte_struct.unpack_from(p, off)[0]
                if instopt == 1:
                    raise LoginError('Invalid instance name')
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
        from pytds import intversion
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
        mins_fix = int(login.client_tz.utcoffset(datetime.now()).total_seconds()) // 60
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

    def fetchone(self, as_dict):
        if self.res_info is None:
            raise Error("Previous statement didn't produce any results")

        if not self.next_row():
            return None

        cols = self.res_info.columns
        row = tuple(self.row)
        if as_dict:
            row = dict((col.column_name, col.value) for col in cols if col.column_name)
        return row

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
                if self.done_flags & TDS_DONE_MORE_RESULTS and not self.done_flags & TDS_DONE_COUNT:
                    # skip results that don't event have rowcount
                    continue
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

    def login(self, login, sock):
        self.login = None
        self._bufsize = login.blocksize
        self.query_timeout = login.query_timeout
        self._main_session = _TdsSession(self, self)
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
            self._main_session = _TdsSession(self, self._smp_manager.create_session())
        self._is_connected = True
        q = []
        if text_size:
            q.append('set textsize {0}'.format(int(text_size)))
        if login.database and self.env.database != login.database:
            q.append('use ' + tds_quote_id(self, login.database))
        if q:
            self._main_session.submit_plain_query(''.join(q))
            self._main_session.process_simple_request()

    @property
    def mars_enabled(self):
        return self._mars_enabled

    @property
    def main_session(self):
        return self._main_session

    def create_session(self):
        return _TdsSession(self, self._smp_manager.create_session())

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

    def VarBinary(self, size):
        if IS_TDS72_PLUS(self):
            return VarBinary72(size)
        else:
            return VarBinary(size)

    def Image(self, size, parts):
        if IS_TDS72_PLUS(self):
            return Image72(size, parts)
        else:
            return Image(size, parts[0])

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
            return VarBinary72(0xffff)
        else:
            return Image()

    def long_string_type(self, collation=raw_collation):
        if IS_TDS72_PLUS(self):
            return NVarChar72(0xffff, collation)
        elif IS_TDS71_PLUS(self):
            return NText71(-1, '', collation)
        else:
            return NText()


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
        return '<Column(name={}, value={}, type={})>'.format(repr(self.column_name), repr(self.value), repr(self.type))


class _Results(object):
    def __init__(self):
        self.columns = []
        self.row_count = 0


#
# Get port of all instances
# @return default port number or 0 if error
# @remark experimental, cf. MC-SQLR.pdf.
#
def tds7_get_instances(ip_addr):
    s = socket.socket(type=socket.SOCK_DGRAM)
    name = None
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
