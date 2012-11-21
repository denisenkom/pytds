import struct
from tdsproto import *


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

client2ucs2             = 0
client2server_chardata  = 1
iso2server_metadata     = 2
initial_char_conv_count = 3 # keep last

TDS_CHARSET_ISO_8859_1  = 1
TDS_CHARSET_CP1251      = 2
TDS_CHARSET_CP1252      = 3
TDS_CHARSET_UCS_2LE     = 4

TDS_CHARSET_UNICODE     = 5

TDS_ENCODING_INDIRECT   = 1
TDS_ENCODING_SWAPBYTE   = 2
TDS_ENCODING_MEMCPY     = 4

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

def tds_conn(tds): return tds.conn

def TDS_IS_SOCKET_INVALID(sock):
    return sock is None

def IS_TDSDEAD(tds):
    return tds is None or tds._sock is None

TDS_DEF_SERVER		= "SYBASE"
TDS_DEF_BLKSZ		= 512
TDS_DEF_CHARSET		= "iso_1"
TDS_DEF_LANG		= "us_english"

def tds_set_ctx(tds, ctx):
    tds.conn.tds_ctx = ctx

def tds_get_ctx(tds):
    return tds.conn.tds_ctx

def tds_set_parent(tds, parent):
    tds.conn.parent = parent

def tds_get_parent(tds):
    return tds.conn.parent

def tds_set_s(tds, sock):
    tds._sock = sock

def tds_get_s(tds):
    return tds._sock

TDS_ADDITIONAL_SPACE = 0

to_server = 0
to_client = 1

def tds_free_row(a, b):
    pass

TDS_DATETIME = struct.Struct('<ll')
TDS_DATETIME4 = struct.Struct('<HH')

#
# Convert from db date format to a structured date format
# @param datetype source date type. SYBDATETIME or SYBDATETIME4
# @param di       source date
# @param dr       destination date
# @return TDS_FAIL or TDS_SUCCESS
#
def tds_datecrack(datetype, di):
    if datetype == (SYBMSDATE, SYBMSTIME, SYBMSDATETIME2, SYBMSDATETIMEOFFSET):
        # I think this is not a real wire format
        raise Exception('not implemented')
        #const TDS_DATETIMEALL *dta = (const TDS_DATETIMEALL *) di;
        #dt_days = (datetype == SYBMSTIME) ? 0 : dta->date;
        #if (datetype == SYBMSDATE) {
        #    dms = 0;
        #    secs = 0;
        #    dt_time = 0;
        #} else {
        #    dms = dta->time % 10000000u;
        #    dt_time = dta->time / 10000000u;
        #    secs = dt_time % 60;
        #    dt_time = dt_time / 60;
        #}
        #if (datetype == SYBMSDATETIMEOFFSET) {
        #    --dt_days;
        #    dt_time = dt_time + 86400 + dta->offset;
        #    dt_days += dt_time / 86400;
        #    dt_time %= 86400;
        #}
    elif datetype == SYBDATETIME or datetype == SYBDATETIMN and len(di) == 8:
        dt_days, dt_time = TDS_DATETIME.unpack(di)
        dms = ((dt_time % 300) * 1000 + 150) / 300 * 10000
        dt_time = dt_time / 300
        secs = dt_time % 60
        dt_time = dt_time / 60
    elif datetype == SYBDATETIME4 or datetype == SYBDATETIMN and len(di) == 4:
        dt_days, dt_time = TDS_DATETIME4.unpack(di)
        secs = 0;
        dms = 0;
    else:
        raise Exception('TDS_FAIL')

    #
    # -53690 is minimun  (1753-1-1) (Gregorian calendar start in 1732) 
    # 2958463 is maximun (9999-12-31)
    #
    l = dt_days + (146038 + 146097*4)
    #wday = (l + 4) % 7
    n = (4 * l) / 146097 # n century
    l = l - (146097 * n + 3) / 4 # days from xx00-02-28 (y-m-d)
    i = (4000 * (l + 1)) / 1461001 # years from xx00-02-28
    l = l - (1461 * i) / 4 # year days from xx00-02-28
    #ydays = l - 305 if l >= 306 else l + 60
    l += 31
    j = (80 * l) / 2447
    days = l - (2447 * j) / 80
    l = j / 11
    months = j + 1 - 12 * l
    years = 100 * (n - 1) + i + l
    #if l == 0 and (years & 3) == 0 and (years % 100 != 0 or years % 400 == 0):
    #    ++ydays

    hours = dt_time / 60
    mins = dt_time % 60

    from datetime import datetime

    return datetime(years, months + 1, days, hours, mins, secs, dms/10)

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
