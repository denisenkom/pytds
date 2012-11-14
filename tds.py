from tdsproto import *

TDS_IDLE = 0
TDS_QUERYING = 1
TDS_PENDING = 2
TDS_READING = 3
TDS_DEAD = 4
state_names = ['IDLE', 'QUERYING', 'PENDING', 'READING', 'DEAD']

TDS_ENCRYPTION_OFF = 0
TDS_ENCRYPTION_REQUEST = 1
TDS_ENCRYPTION_REQUIRE = 2

#define IS_TDS42(x) (x->tds_version==0x402)
#define IS_TDS46(x) (x->tds_version==0x406)
def IS_TDS50(x): return x.tds_version==0x500
#define IS_TDS70(x) (x->tds_version==0x700)
#define IS_TDS71(x) (x->tds_version==0x701)
def IS_TDS72(x): return x.tds_version==0x702
#define IS_TDS73(x) (x->tds_version==0x703)
def IS_TDS7_PLUS(x): return x.tds_version>=0x700
def IS_TDS71_PLUS(x): return x.tds_version>=0x701
def IS_TDS72_PLUS(x): return x.tds_version>=0x702
#define IS_TDS73_PLUS(x) ((x)->tds_version>=0x703)

client2ucs2             = 0
client2server_chardata  = 1
iso2server_metadata     = 2
initial_char_conv_count = 3 # keep last

TDS_CHARSET_ISO_8859_1 = 1
TDS_CHARSET_CP1251     = 2
TDS_CHARSET_CP1252     = 3
TDS_CHARSET_UCS_2LE    = 4


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


TDS_TOKEN_RESULTS = TDS_RETURN_ROWFMT|TDS_RETURN_COMPUTEFMT|TDS_RETURN_DONE|TDS_STOPAT_ROW|TDS_STOPAT_COMPUTE|TDS_RETURN_PROC
TDS_TOKEN_TRAILING = TDS_STOPAT_ROWFMT|TDS_STOPAT_COMPUTEFMT|TDS_STOPAT_ROW|TDS_STOPAT_COMPUTE|TDS_STOPAT_MSG|TDS_STOPAT_OTHERS

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
#define is_numeric_type(x) (x==SYBNUMERIC || x==SYBDECIMAL)
def is_unicode_type(x): return x in (XSYBNVARCHAR,XSYBNCHAR,SYBNTEXT,SYBMSXML)
#define is_collate_type(x) (x==XSYBVARCHAR || x==XSYBCHAR || x==SYBTEXT || x==XSYBNVARCHAR || x==XSYBNCHAR || x==SYBNTEXT)
def is_ascii_type(x): return x in (XSYBCHAR,XSYBVARCHAR,SYBTEXT,SYBCHAR,SYBVARCHAR)
#define is_char_type(x) (is_unicode_type(x) || is_ascii_type(x))
#define is_similar_type(x, y) ((is_char_type(x) && is_char_type(y)) || ((is_unicode_type(x) && is_unicode_type(y))))

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

def tds_set_parent(tds, parent):
    tds.conn.parent = parent

def tds_get_parent(tds):
    return tds.conn.parent

def tds_set_s(tds, sock):
    tds._sock = sock

def tds_get_s(tds):
    return tds._sock

TDS_ADDITIONAL_SPACE = 0
