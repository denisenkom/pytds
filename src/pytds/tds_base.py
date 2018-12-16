import socket
import sys

import six

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


# https://msdn.microsoft.com/en-us/library/dd304214.aspx
class PacketType:
    QUERY = 1
    OLDLOGIN = 2
    RPC = 3
    REPLY = 4
    CANCEL = 6
    BULK = 7
    FEDAUTHTOKEN = 8
    TRANS = 14  # transaction management
    LOGIN = 16
    AUTH = 17
    PRELOGIN = 18


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

# enum option_flag2_values
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

# enum option_flag3_values TDS 7.3+
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
TDS_ENV_UNICODE_DATA_SORT_COMP_FLAGS = 6
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
TVPTYPE = 243  # 0xF3
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

class PreLoginToken:
    VERSION = 0
    ENCRYPTION = 1
    INSTOPT = 2
    THREADID = 3
    MARS = 4
    TRACEID = 5
    FEDAUTHREQUIRED = 6
    NONCEOPT = 7
    TERMINATOR = 0xff

class PreLoginEnc:
    ENCRYPT_OFF = 0  # Encryption available but off
    ENCRYPT_ON = 1  # Encryption available and on
    ENCRYPT_NOT_SUP = 2  # Encryption not available
    ENCRYPT_REQ = 3  # Encryption required

PLP_MARKER = 0xffff
PLP_NULL = 0xffffffffffffffff
PLP_UNKNOWN = 0xfffffffffffffffe

TDS_NO_COUNT = -1

TVP_NULL_TOKEN = 0xffff

# TVP COLUMN FLAGS
TVP_COLUMN_DEFAULT_FLAG = 0x200

TVP_END_TOKEN = 0x00
TVP_ROW_TOKEN = 0x01
TVP_ORDER_UNIQUE_TOKEN = 0x10
TVP_COLUMN_ORDERING_TOKEN = 0x11


class CommonEqualityMixin(object):
    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__eq__(other)


def iterdecode(iterable, codec):
    """ Uses an incremental decoder to decode each chunk in iterable.
    This function is a generator.

    :param iterable: Iterable object which yields raw data to be decoded
    :param codec: An instance of codec
    """
    decoder = codec.incrementaldecoder()
    for chunk in iterable:
        yield decoder.decode(chunk)
    yield decoder.decode(b'', True)


def force_unicode(s):
    if isinstance(s, bytes):
        try:
            return s.decode('utf8')
        except UnicodeDecodeError as e:
            raise DatabaseError(e)
    elif isinstance(s, six.text_type):
        return s
    else:
        return six.text_type(s)


def tds_quote_id(ident):
    """ Quote an identifier

    :param ident: id to quote
    :returns: Quoted identifier
    """
    return '[{0}]'.format(ident.replace(']', ']]'))


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

    def my_ord(val):
        return val

    def join_bytearrays(ba):
        return b''.join(ba)

else:
    exc_base_class = StandardError
    my_ord = ord

    def join_bytearrays(bas):
        return b''.join(bytes(ba) for ba in bas)

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


# DB-API type definitions
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


class InternalProc(object):
    def __init__(self, proc_id, name):
        self.proc_id = proc_id
        self.name = name

    def __unicode__(self):
        return self.name

SP_EXECUTESQL = InternalProc(TDS_SP_EXECUTESQL, 'sp_executesql')
SP_PREPARE = InternalProc(TDS_SP_PREPARE, 'sp_prepare')
SP_EXECUTE = InternalProc(TDS_SP_EXECUTE, 'sp_execute')


def skipall(stm, size):
    """ Skips exactly size bytes in stm

    If EOF is reached before size bytes are skipped
    will raise :class:`ClosedConnectionError`

    :param stm: Stream to skip bytes in, should have read method
                this read method can return less than requested
                number of bytes.
    :param size: Number of bytes to skip.
    """
    res = stm.recv(size)
    if len(res) == size:
        return
    elif len(res) == 0:
        raise ClosedConnectionError()
    left = size - len(res)
    while left:
        buf = stm.recv(left)
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

    res = stm.recv(size)
    if len(res) == 0:
        raise ClosedConnectionError()
    yield res
    left = size - len(res)
    while left:
        buf = stm.recv(left)
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
    return join_bytearrays(read_chunks(stm, size))


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
        buf += stm.recv(size - len(buf))
        return buf, 0
    return buf, offset


def total_seconds(td):
    """ Total number of seconds in timedelta object

    Python 2.6 doesn't have total_seconds method, this function
    provides a backport
    """
    return td.days * 24 * 60 * 60 + td.seconds


class Column(CommonEqualityMixin):
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
        self.serializer = None

    def __repr__(self):
        val = self.value
        if isinstance(val, bytes) and len(self.value) > 100:
            val = self.value[:100] + b'... len is ' + str(len(val)).encode('ascii')
        if isinstance(val, six.text_type) and len(self.value) > 100:
            val = self.value[:100] + '... len is ' + str(len(val))
        return '<Column(name={},type={},value={},flags={},user_type={},codec={})>'.format(
            repr(self.column_name),
            repr(self.type),
            repr(val),
            repr(self.flags),
            repr(self.column_usertype),
            repr(self.char_codec),
        )

    def choose_serializer(self, type_factory, collation):
        return type_factory.serializer_by_type(sql_type=self.type, collation=collation)
