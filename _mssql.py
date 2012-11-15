# vim: set fileencoding=utf8 :
import logging
import decimal
import datetime
import re
from tds import *
from mem import *
from login import *
from config import *
from query import *

logger = logging.getLogger(__name__)

#############################
## DB-API type definitions ##
#############################
STRING = 1
BINARY = 2
NUMBER = 3
DATETIME = 4
DECIMAL = 5

##################
## DB-LIB types ##
##################
SQLBINARY = SYBBINARY
SQLBIT = SYBBIT
SQLBITN = 104
SQLCHAR = SYBCHAR
SQLDATETIME = SYBDATETIME
SQLDATETIM4 = SYBDATETIME4
SQLDATETIMN = SYBDATETIMN
SQLDECIMAL = SYBDECIMAL
SQLFLT4 = SYBREAL
SQLFLT8 = SYBFLT8
SQLFLTN = SYBFLTN
SQLIMAGE = SYBIMAGE
SQLINT1 = SYBINT1
SQLINT2 = SYBINT2
SQLINT4 = SYBINT4
SQLINT8 = SYBINT8
SQLINTN = SYBINTN
SQLMONEY = SYBMONEY
SQLMONEY4 = SYBMONEY4
SQLMONEYN = SYBMONEYN
SQLNUMERIC = SYBNUMERIC
SQLREAL = SYBREAL
SQLTEXT = SYBTEXT
SQLVARBINARY = SYBVARBINARY
SQLVARCHAR = SYBVARCHAR
SQLUUID = 36

#######################
## Exception classes ##
#######################
class MSSQLException(Exception):
    """
    Base exception class for the MSSQL driver.
    """

class MSSQLDriverException(MSSQLException):
    """
    Inherits from the base class and raised when an error is caused within
    the driver itself.
    """

class MSSQLDatabaseException(MSSQLException):
    """
    Raised when an error occurs within the database.
    """

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

DB_RES_INIT            = 0
DB_RES_RESULTSET_EMPTY = 1
DB_RES_RESULTSET_ROWS  = 2
DB_RES_NEXT_RESULT     = 3
DB_RES_NO_MORE_RESULTS = 4
DB_RES_SUCCEED         = 5

def prdbresults_state(retcode):
    if retcode == DB_RES_INIT:                 return "DB_RES_INIT"
    elif retcode == DB_RES_RESULTSET_EMPTY:    return "DB_RES_RESULTSET_EMPTY"
    elif retcode == DB_RES_RESULTSET_ROWS:     return "DB_RES_RESULTSET_ROWS"
    elif retcode == DB_RES_NEXT_RESULT:        return "DB_RES_NEXT_RESULT"
    elif retcode == DB_RES_NO_MORE_RESULTS:    return "DB_RES_NO_MORE_RESULTS"
    elif retcode == DB_RES_SUCCEED:            return "DB_RES_SUCCEED"
    else: return "oops: %d ??" % retcode

REG_ROW         = -1
MORE_ROWS       = -1
NO_MORE_ROWS    = -2
BUF_FULL        = -3
NO_MORE_RESULTS = 2
SUCCEED         = 1
FAIL            = 0

def prdbretcode(retcode):
    if retcode == REG_ROW:            return "REG_ROW/MORE_ROWS"
    elif retcode == NO_MORE_ROWS:       return "NO_MORE_ROWS"
    elif retcode == BUF_FULL:           return "BUF_FULL"
    elif retcode == NO_MORE_RESULTS:    return "NO_MORE_RESULTS"
    elif retcode == SUCCEED:            return "SUCCEED"
    elif retcode == FAIL:               return "FAIL"
    else: return "oops: %u ??" % retcode

def prretcode(retcode):
    if retcode == TDS_SUCCESS:                  return "TDS_SUCCESS"
    elif retcode == TDS_FAIL:                   return "TDS_FAIL"
    elif retcode == TDS_NO_MORE_RESULTS:        return "TDS_NO_MORE_RESULTS"
    elif retcode == TDS_CANCELLED:              return "TDS_CANCELLED"
    else: return "oops: %u ??" % retcode

def prresult_type(result_type):
    if result_type == TDS_ROW_RESULT:          return "TDS_ROW_RESULT"
    elif result_type == TDS_PARAM_RESULT:      return "TDS_PARAM_RESULT"
    elif result_type == TDS_STATUS_RESULT:     return "TDS_STATUS_RESULT"
    elif result_type == TDS_MSG_RESULT:        return "TDS_MSG_RESULT"
    elif result_type == TDS_COMPUTE_RESULT:    return "TDS_COMPUTE_RESULT"
    elif result_type == TDS_CMD_DONE:          return "TDS_CMD_DONE"
    elif result_type == TDS_CMD_SUCCEED:       return "TDS_CMD_SUCCEED"
    elif result_type == TDS_CMD_FAIL:          return "TDS_CMD_FAIL"
    elif result_type == TDS_ROWFMT_RESULT:     return "TDS_ROWFMT_RESULT"
    elif result_type == TDS_COMPUTEFMT_RESULT: return "TDS_COMPUTEFMT_RESULT"
    elif result_type == TDS_DESCRIBE_RESULT:   return "TDS_DESCRIBE_RESULT"
    elif result_type == TDS_DONE_RESULT:       return "TDS_DONE_RESULT"
    elif result_type == TDS_DONEPROC_RESULT:   return "TDS_DONEPROC_RESULT"
    elif result_type == TDS_DONEINPROC_RESULT: return "TDS_DONEINPROC_RESULT"
    elif result_type == TDS_OTHERS_RESULT:     return "TDS_OTHERS_RESULT"
    else: "oops: %u ??" % result_type

# Module attributes for configuring _mssql
login_timeout = 60
query_timeout = 60

min_error_severity = 6

###########################
## Compatibility Aliases ##
###########################
def connect(*args, **kwargs):
    return MSSQLConnection(*args, **kwargs)

def clr_err(conn):
    conn.last_msg_no = 0
    conn.last_msg_severity = 0
    conn.last_msg_state = 0

def db_cancel(conn):
    if conn == None:
        return

    if conn.dbproc is None:
        return

    tds_send_cancel(conn.dbproc.tds_socket)
    tds_process_cancel(conn.dbproc.tds_socket)

    conn.clear_metadata()

def _tds_ver_str_to_constant(verstr):
    """
        http://www.freetds.org/userguide/choosingtdsprotocol.htm
    """
    if verstr == u'4.2':
        return 0x402
    elif verstr == u'7.0':
        return 0x700
    elif verstr == u'7.1':
        return 0x701
    elif verstr == u'7.2':
        return 0x702
    elif verstr == '7.3':
        return 0x703
    #elif verstr == u'8.0':
    #    return 0x800
    else:
        raise MSSQLException('unrecognized tds version: %s' % verstr)

#######################
## Quoting Functions ##
#######################
def _quote_simple_value(value, charset='utf8'):

    if value == None:
        return 'NULL'

    if isinstance(value, bool):
        return '1' if value else '0'

    if isinstance(value, float):
        return repr(value)

    if isinstance(value, (int, long, decimal.Decimal)):
        return str(value)

    if isinstance(value, str):
        # see if it can be decoded as ascii if there are no null bytes
        if '\0' not in value:
            try:
                value.decode('ascii')
                return "'" + value.replace("'", "''") + "'"
            except UnicodeDecodeError:
                pass

        # will still be string type if there was a null byte in it or if the
        # decoding failed.  In this case, just send it as hex.
        if isinstance(value, str):
            return '0x' + value.encode('hex')

    if isinstance(value, unicode):
        return "N'" + value.encode(charset).replace("'", "''") + "'"

    if isinstance(value, datetime.datetime):
        return "{ts '%04d-%02d-%02d %02d:%02d:%02d.%d'}" % (
            value.year, value.month, value.day,
            value.hour, value.minute, value.second,
            value.microsecond / 1000)

    if isinstance(value, datetime.date):
        return "{d '%04d-%02d-%02d'} " % (
        value.year, value.month, value.day)

    return None

def _quote_or_flatten(data, charset='utf8'):
    result = _quote_simple_value(data, charset)

    if result is not None:
        return result

    if not issubclass(type(data), (list, tuple)):
        raise ValueError('expected a simple type, a tuple or a list')

    quoted = []
    for value in data:
        value = _quote_simple_value(value, charset)

        if value is None:
            raise ValueError('found an unsupported type')

        quoted.append(value)
    return '(' + ','.join(quoted) + ')'

# This function is supposed to take a simple value, tuple or dictionary,
# normally passed in via the params argument in the execute_* methods. It
# then quotes and flattens the arguments and returns then.
def _quote_data(data, charset='utf8'):
    result = _quote_simple_value(data)

    if result is not None:
        return result

    if issubclass(type(data), dict):
        result = {}
        for k, v in data.iteritems():
            result[k] = _quote_or_flatten(v, charset)
        return result

    if issubclass(type(data), (tuple, list)):
        result = []
        for v in data:
            result.append(_quote_or_flatten(v, charset))
        return tuple(result)

    raise ValueError('expected a simple type, a tuple or a dictionary.')

_re_pos_param = re.compile(r'(%(s|d))')
_re_name_param = re.compile(r'(%\(([^\)]+)\)s)')
def _substitute_params(toformat, params, charset):
    if params is None:
        return toformat

    if not issubclass(type(params),
            (bool, int, long, float, unicode, str,
            datetime.datetime, datetime.date, dict, tuple, decimal.Decimal, list)):
        raise ValueError("'params' arg can be only a tuple or a dictionary.")

    if charset:
        quoted = _quote_data(params, charset)
    else:
        quoted = _quote_data(params)

    # positional string substitution now requires a tuple
    if isinstance(quoted, basestring):
        quoted = (quoted,)

    if isinstance(params, dict):
        """ assume name based substitutions """
        offset = 0
        for match in _re_name_param.finditer(toformat):
            param_key = match.group(2)

            if not params.has_key(param_key):
                raise ValueError('params dictionary did not contain value for placeholder: %s' % param_key)

            # calculate string positions so we can keep track of the offset to
            # be used in future substituations on this string.  This is
            # necessary b/c the match start() and end() are based on the
            # original string, but we modify the original string each time we
            # loop, so we need to make an adjustment for the difference between
            # the length of the placeholder and the length of the value being
            # substituted
            param_val = quoted[param_key]
            param_val_len = len(param_val)
            placeholder_len = len(match.group(1))
            offset_adjust = param_val_len - placeholder_len

            # do the string substitution
            match_start = match.start(1) + offset
            match_end = match.end(1) + offset
            toformat = toformat[:match_start] + param_val + toformat[match_end:]

            # adjust the offset for the next usage
            offset += offset_adjust
    else:
        """ assume position based substitutions """
        offset = 0
        for count, match in enumerate(_re_pos_param.finditer(toformat)):
            # calculate string positions so we can keep track of the offset to
            # be used in future substituations on this string.  This is
            # necessary b/c the match start() and end() are based on the
            # original string, but we modify the original string each time we
            # loop, so we need to make an adjustment for the difference between
            # the length of the placeholder and the length of the value being
            # substituted
            try:
                param_val = quoted[count]
            except IndexError:
                raise ValueError('more placeholders in sql than params available')
            param_val_len = len(param_val)
            placeholder_len = 2
            offset_adjust = param_val_len - placeholder_len

            # do the string substitution
            match_start = match.start(1) + offset
            match_end = match.end(1) + offset
            toformat = toformat[:match_start] + param_val + toformat[match_end:]
            #print(param_val, param_val_len, offset_adjust, match_start, match_end)
            # adjust the offset for the next usage
            offset += offset_adjust
    return toformat

# We'll add these methods to the module to allow for unit testing of the
# underlying C methods.
def quote_simple_value(value):
    return _quote_simple_value(value)

def quote_or_flatten(data):
    return _quote_or_flatten(data)

def quote_data(data):
    return _quote_data(data)

def substitute_params(toformat, params, charset='utf8'):
    return _substitute_params(toformat, params, charset)

##############################
## MSSQL Row Iterator Class ##
##############################
class MSSQLRowIterator:

    def __init__(self, connection):
        self.conn = connection

    def __iter__(self):
        return self

    def next(self):
        assert_connected(self.conn)
        clr_err(self.conn)
        if self.conn.as_dict:
            return self.conn.fetch_next_row_dict(1)
        else:
            return self.conn.fetch_next_row(1)

############################
## MSSQL Connection Class ##
############################
class MSSQLConnection(object):
    @property
    def connected(self):
        """
        True if the connection to a database is open.
        """
        return self._connected

    @property
    def rows_affected(self):
        """
        Number of rows affected by last query. For SELECT statements this
        value is only meaningful after reading all rows.
        """
        return self._rows_affected

    def __init__(self, server="localhost", user="sa", password="",
            charset='', database='', appname=None, port='1433', tds_version='7.1',
            as_dict=True):
        logger.debug("_mssql.MSSQLConnection.__cinit__()")
        self._connected = 0
        self._charset = ''
        self.last_msg_no = 0
        self.last_msg_severity = 0
        self.last_msg_state = 0
        self.last_msg_str = ''
        self.last_msg_srv = ''
        self.last_msg_proc = ''
        self.column_names = None
        self.column_types = None
        self.as_dict = as_dict
        self.dbproc = None

        # support MS methods of connecting locally
        instance = ""
        if "\\" in server:
            server, instance = server.split("\\")

        if server in (".", "(local)"):
            server = "localhost"

        server = server + "\\" + instance if instance else server

        login = tds_alloc_login(1)
        # set default values for loginrec
        login.library = "DB-Library"

        appname = appname or "pymssql"

        login.user_name = user
        login.password = password
        login.app = appname
        login.tds_version = _tds_ver_str_to_constant(tds_version)
        login.database = database

        # override the HOST to be the portion without the server, otherwise
        # FreeTDS chokes when server still has the port definition.
        # BUT, a patch on the mailing list fixes the need for this.  I am
        # leaving it here just to remind us how to fix the problem if the bug
        # doesn't get fixed for a while.  But if it does get fixed, this code
        # can be deleted.
        # patch: http://lists.ibiblio.org/pipermail/freetds/2011q2/026997.html
        #if ':' in server:
        #    os.environ['TDSHOST'] = server.split(':', 1)[0]
        #else:
        #    os.environ['TDSHOST'] = server

        # Set the character set name
        if charset:
            _charset = charset
            self._charset = _charset
            login.charset = self._charset

        # Connect to the server
        msdblib = True
        try:
            dbproc = self
            self.dbproc = dbproc
            dbproc.msdblib = msdblib
            tds_set_server(login, server)
            ctx = tds_alloc_context()
            ctx.msg_handler = self._msg_handler
            ctx.err_handler = self._err_handler
            ctx.int_handler = self._int_handler
            dbproc.tds_socket = tds_alloc_socket(ctx, 512)
            tds_set_parent(dbproc.tds_socket, dbproc)
            dbproc.tds_socket.env_chg_func = self._db_env_chg
            dbproc.envchange_rcv = 0
            dbproc.dbcurdb = ''
            dbproc.servcharset = ''
            login.option_flag2 &= ~0x02 # we're not an ODBC driver
            tds_fix_login(login) # initialize from Environment variables

            login.connect_timeout = login_timeout
            login.query_timeout = query_timeout

            tds_connect_and_login(dbproc.tds_socket, login)
        except Exception:
            logger.exception("_mssql.MSSQLConnection.__init__() connection failed")
            maybe_raise_MSSQLDatabaseException(self)
            raise MSSQLDriverException("Connection to the database failed for an unknown reason.")

        self._connected = 1

        return

        logger.debug("_mssql.MSSQLConnection.__init__() -> dbcmd() setting connection values")
        # Set some connection properties to some reasonable values
        query =\
            "SET ARITHABORT ON;"                \
            "SET CONCAT_NULL_YIELDS_NULL ON;"   \
            "SET ANSI_NULLS ON;"                \
            "SET ANSI_NULL_DFLT_ON ON;"         \
            "SET ANSI_PADDING ON;"              \
            "SET ANSI_WARNINGS ON;"             \
            "SET ANSI_NULL_DFLT_ON ON;"         \
            "SET CURSOR_CLOSE_ON_COMMIT ON;"    \
            "SET QUOTED_IDENTIFIER ON;"         \
            "SET TEXTSIZE 2147483647;" # http://msdn.microsoft.com/en-us/library/aa259190%28v=sql.80%29.aspx

        #dbsqlsend() begin
        tds = self.dbproc.tds_socket
        if tds.state == TDS_PENDING:
            raise Exception('not implemented')
            #if (tds_process_tokens(tds, &result_type, NULL, TDS_TOKEN_TRAILING) != TDS_NO_MORE_RESULTS) {
            #        dbperror(dbproc, SYBERPND, 0);
            #        dbproc->command_state = DBCMDSENT;
            #        return FAIL;
            #}
        tds_submit_query(tds, query)

        #dbsqlsend() end
        #dbsqlok() begin
        while True:
            rc, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)
            if done_flags & TDS_DONE_ERROR:
                raise MSSQLDriverException("Could not set connection properties")
            if rc == TDS_NO_MORE_RESULTS:
                break
            elif rc == TDS_SUCCESS:
                if result_type == TDS_ROWFMT_RESULT:
                    pass
                elif result_type == TDS_COMPUTEFMT_RESULT:
                    pass
                elif result_type in (TDS_COMPUTE_RESULT, TDS_ROW_RESULT):
                    logger.debug("dbsqlok() found result token")
                    break
                elif result_type == TDS_DONEINPROC_RESULT:
                    pass
                elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                    logger.debug("dbsqlok() end status is {0}".format(return_code))
                    if done_flags & TDS_DONE_ERROR:
                        raise MSSQLDriverException("Could not set connection properties")
                    else:
                        logger.debug("dbsqlok() end status was success")
                        break
                else:
                    logger.error("logic error: tds_process_tokens result_type {0}".format(result_type))
                    break;
                break;
        else:
            assert TDS_FAILED(rc)
            raise MSSQLDriverException("Could not set connection properties")

        #dbsqlok() end
        #if (rtc == FAIL):
        #    raise MSSQLDriverException("Could not set connection properties")

        db_cancel(self)
        clr_err(self)

    def _int_handler(self):
        raise Exception('not implemented')

    def _err_handler(self, tds_ctx, tds, msg):
        self._msg_handler(tds_ctx, tds, msg)

    def _msg_handler(self, tds_ctx, tds, msg):
        if msg['severity'] < min_error_severity:
            return
        if msg['severity'] > self.last_msg_severity:
            self.last_msg_severity = msg['severity']
            self.last_msg_no = msg['msgno']
            self.last_msg_state = msg['state']
            self.last_msg_line = msg['line_number']
            self.last_msg_str = msg['message']
            self.last_msg_srv = msg['server']
            self.last_msg_proc = msg['proc_name']

    def _db_env_chg(self, tds, type, oldval, newval):
        assert oldval is not None and newval is not None
        if oldval == '\x01':
            oldval = "(0x1)"

        logger.debug("db_env_chg(%d, %s, %s)", type, oldval, newval)

        dbproc = self.dbproc
        dbproc.envchange_rcv |= (1 << (type - 1))
        if type == TDS_ENV_DATABASE:
            dbproc.dbcurdb = newval
        elif type == TDS_ENV_CHARSET:
            dbproc.servcharset = newval
        def __del__(self):
            logger.debug("_mssql.MSSQLConnection.__dealloc__()")
            self.close()

    def __iter__(self):
        assert_connected(self)
        clr_err(self)
        return MSSQLRowIterator(self)

    def cancel(self):
        """
        cancel() -- cancel all pending results.

        This function cancels all pending results from the last SQL operation.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        logger.debug("_mssql.MSSQLConnection.cancel()")
        assert_connected(self)
        clr_err(self)

        rtc = db_cancel(self)
        check_and_raise(rtc, self)

    def clear_metadata(self):
        logger.debug("_mssql.MSSQLConnection.clear_metadata()")
        self.column_names = None
        self.column_types = None
        self.num_columns = 0
        self.last_dbresults = 0

    def close(self):
        """
        close() -- close connection to an MS SQL Server.

        This function tries to close the connection and free all memory used.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        logger.debug("_mssql.MSSQLConnection.close()")
        if self == None:
            return None

        if not self._connected:
            return None

        clr_err(self)

        tds = self.dbproc.tds_socket
        if tds:
            tds_free_socket(tds)
        self.dbproc = None

        self._connected = 0

    def convert_db_value(self, data, type, length):
        logger.debug("_mssql.MSSQLConnection.convert_db_value()")

        if type in (SQLBIT, SQLBITN):
            return bool(struct.unpack('B', data)[0])

        elif type == SQLINT1 or type == SYBINTN and length == 1:
            return struct.unpack('b', data)[0]

        elif type == SQLINT2 or type == SYBINTN and length == 2:
            return struct.unpack('<h', data)[0]

        elif type == SQLINT4 or type == SYBINTN and length == 4:
            return struct.unpack('<l', data)[0]

        elif type == SQLINT8 or type == SYBINTN and length == 8:
            return struct.unpack('<q', data)[0]

        elif type == SQLFLT4 or type == SYBFLTN and length == 4:
            return struct.unpack('f', data)[0]

        elif type == SQLFLT8 or type == SYBFLTN and length == 8:
            return struct.unpack('d', data)[0]

        elif type in (SQLMONEY, SQLMONEY4, SQLNUMERIC, SQLDECIMAL):
            raise Exception('not implemented')
            #dbcol.SizeOfStruct = sizeof(dbcol)

            #if type in (SQLMONEY, SQLMONEY4):
            #    precision = 4
            #else:
            #    precision = dbcol.Scale

            #len = dbconvert(self.dbproc, type, data, -1, SQLCHAR,
            #    <BYTE *>buf, NUMERIC_BUF_SZ)

            #with decimal.localcontext() as ctx:
            #    ctx.prec = precision
            #    return decimal.Decimal(_remove_locale(buf, len))

        elif type in (SQLDATETIME, SQLDATETIM4, SQLDATETIMN):
            return tds_datecrack(type, data)

        elif type in (SQLVARCHAR, SQLCHAR, SQLTEXT):
            if self._charset:
                return data[:length].decode(self._charset)
            else:
                return data[:length]

        elif type == SQLUUID and (PY_MAJOR_VERSION >= 2 and PY_MINOR_VERSION >= 5):
            raise Exception('not implemented')
            #return uuid.UUID(bytes_le=(<char *>data)[:length])

        else:
            return data[:length]

    def select_db(self, dbname):
        """
        select_db(dbname) -- Select the current database.

        This function selects the given database. An exception is raised on
        failure.
        """
        logger.debug("_mssql.MSSQLConnection.select_db()")

        dbuse(self.dbproc, dbname)

    def execute_non_query(self, query_string, params=None):
        """
        execute_non_query(query_string, params=None)

        This method sends a query to the MS SQL Server to which this object
        instance is connected. After completion, its results (if any) are
        discarded. An exception is raised on failure. If there are any pending
        results or rows prior to executing this command, they are silently
        discarded. This method accepts Python formatting. Please see
        execute_query() for more details.

        This method is useful for INSERT, UPDATE, DELETE and for Data
        Definition Language commands, i.e. when you need to alter your database
        schema.

        After calling this method, rows_affected property contains number of
        rows affected by the last SQL command.
        """
        logger.debug("_mssql.MSSQLConnection.execute_non_query() BEGIN")

        self.format_and_run_query(query_string, params)
        # getting results
        while True:
            rc, result_type, done_flags = tds_process_tokens(self.dbproc.tds_socket, TDS_TOKEN_RESULTS)
            if done_flags & TDS_DONE_ERROR:
                raise MSSQLDriverException("Could not set connection properties")
            if rc == TDS_NO_MORE_RESULTS:
                break
            elif rc == TDS_SUCCESS:
                if result_type == TDS_ROWFMT_RESULT:
                    pass
                elif result_type == TDS_COMPUTEFMT_RESULT:
                    pass
                elif result_type in (TDS_COMPUTE_RESULT, TDS_ROW_RESULT):
                    logger.debug("dbsqlok() found result token")
                    break
                elif result_type == TDS_DONEINPROC_RESULT:
                    pass
                elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                    logger.debug("dbsqlok() end status is {0}".format(return_code))
                    if done_flags & TDS_DONE_ERROR:
                        raise MSSQLDriverException("Could not set connection properties")
                    else:
                        logger.debug("dbsqlok() end status was success")
                        break
                else:
                    logger.error("logic error: tds_process_tokens result_type {0}".format(result_type))
                    break;
                break;
        else:
            assert TDS_FAILED(rc)
            raise MSSQLDriverException("Could not set connection properties")
        self._rows_affected = self.dbproc.tds_socket.rows_affected

        rtc = db_cancel(self)
        check_and_raise(rtc, self)
        logger.debug("_mssql.MSSQLConnection.execute_non_query() END")

    def execute_query(self, query_string, params=None):
        """
        execute_query(query_string, params=None)

        This method sends a query to the MS SQL Server to which this object
        instance is connected. An exception is raised on failure. If there
        are pending results or rows prior to executing this command, they
        are silently discarded. After calling this method you may iterate
        over the connection object to get rows returned by the query.

        You can use Python formatting here and all values get properly
        quoted:
            conn.execute_query('SELECT * FROM empl WHERE id=%d', 13)
            conn.execute_query('SELECT * FROM empl WHERE id IN (%s)', ((5,6),))
            conn.execute_query('SELECT * FROM empl WHERE name=%s', 'John Doe')
            conn.execute_query('SELECT * FROM empl WHERE name LIKE %s', 'J%')
            conn.execute_query('SELECT * FROM empl WHERE name=%(name)s AND \
                city=%(city)s', { 'name': 'John Doe', 'city': 'Nowhere' } )
            conn.execute_query('SELECT * FROM cust WHERE salesrep=%s \
                AND id IN (%s)', ('John Doe', (1,2,3)))
            conn.execute_query('SELECT * FROM empl WHERE id IN (%s)',\
                (tuple(xrange(4)),))
            conn.execute_query('SELECT * FROM empl WHERE id IN (%s)',\
                (tuple([3,5,7,11]),))

        This method is intented to be used on queries that return results,
        i.e. SELECT. After calling this method AND reading all rows from,
        result rows_affected property contains number of rows returned by
        last command (this is how MS SQL returns it).
        """
        logger.debug("_mssql.MSSQLConnection.execute_query() BEGIN")
        self.format_and_run_query(query_string, params)
        self.get_result()
        logger.debug("_mssql.MSSQLConnection.execute_query() END")

    def execute_row(self, query_string, params=None):
        """
        execute_row(query_string, params=None)

        This method sends a query to the MS SQL Server to which this object
        instance is connected, then returns first row of data from result.

        An exception is raised on failure. If there are pending results or
        rows prior to executing this command, they are silently discarded.

        This method accepts Python formatting. Please see execute_query()
        for details.

        This method is useful if you want just a single row and don't want
        or don't need to iterate, as in:

        conn.execute_row('SELECT * FROM employees WHERE id=%d', 13)

        This method works exactly the same as 'iter(conn).next()'. Remaining
        rows, if any, can still be iterated after calling this method.
        """
        logger.debug("_mssql.MSSQLConnection.execute_row()")
        self.format_and_run_query(query_string, params)
        if self.as_dict:
            return self.fetch_next_row_dict(0)
        else:
            return self.fetch_next_row(0)

    def _nextrow(self):
        result = FAIL
        dbproc = self.dbproc
        logger.debug("_nextrow()")
        tds = dbproc.tds_socket
        resinfo = tds.res_info
        if not resinfo or dbproc.dbresults_state != DB_RES_RESULTSET_ROWS:
            # no result set or result set empty (no rows)
            logger.debug("leaving _nextrow() returning %d (NO_MORE_ROWS)", NO_MORE_ROWS)
            dbproc.row_type = NO_MORE_ROWS
            return NO_MORE_ROWS

        #
        # Try to get the dbproc->row_buf.current item from the buffered rows, if any.  
        # Else read from the stream, unless the buffer is exhausted.  
        # If no rows are read, DBROWTYPE() will report NO_MORE_ROWS. 
        #/
        dbproc.row_type = NO_MORE_ROWS
        computeid = REG_ROW
        mask = TDS_STOPAT_ROWFMT|TDS_RETURN_DONE|TDS_RETURN_ROW|TDS_RETURN_COMPUTE

        # Get the row from the TDS stream.
        rc, res_type, _ = tds_process_tokens(tds, mask)
        if rc == TDS_SUCCESS:
            if res_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                if res_type == TDS_COMPUTE_RESULT:
                    computeid = tds.current_results.computeid
                # Add the row to the row buffer, whose capacity is always at least 1
                resinfo = tds.current_results
                result = dbproc.row_type = REG_ROW if res_type == TDS_ROW_RESULT else computeid
                #_, res_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
            else:
                dbproc.dbresults_state = DB_RES_NEXT_RESULT
                result = NO_MORE_ROWS
        elif rc == TDS_NO_MORE_RESULTS:
            dbproc.dbresults_state = DB_RES_NEXT_RESULT
            result = NO_MORE_ROWS
        else:
            raise Exception("unexpected result from tds_process_tokens")

        if res_type == TDS_COMPUTE_RESULT:
            logger.debug("leaving _nextrow() returning compute_id %d\n", result)
        else:
            logger.debug("leaving _nextrow() returning %s\n", prdbretcode(result))
        return result

    def execute_scalar(self, query_string, params=None):
        """
        execute_scalar(query_string, params=None)

        This method sends a query to the MS SQL Server to which this object
        instance is connected, then returns first column of first row from
        result. An exception is raised on failure. If there are pending

        results or rows prior to executing this command, they are silently
        discarded.

        This method accepts Python formatting. Please see execute_query()
        for details.

        This method is useful if you want just a single value, as in:
            conn.execute_scalar('SELECT COUNT(*) FROM employees')

        This method works in the same way as 'iter(conn).next()[0]'.
        Remaining rows, if any, can still be iterated after calling this
        method.
        """
        logger.debug("_mssql.MSSQLConnection.execute_scalar()")

        self.format_and_run_query(query_string, params)
        self.get_result()

        rtc = self._nextrow()

        self._rows_affected = self.dbproc.tds_socket.rows_affected

        if rtc == NO_MORE_ROWS:
            self.clear_metadata()
            self.last_dbresults = 0
            return None

        return self.get_row(rtc)[0]

    def fetch_next_row(self, throw):
        logger.debug("_mssql.MSSQLConnection.fetch_next_row() BEGIN")
        try:
            self.get_result()

            if self.last_dbresults == NO_MORE_RESULTS:
                logger.debug("_mssql.MSSQLConnection.fetch_next_row(): NO MORE RESULTS")
                self.clear_metadata()
                if throw:
                    raise StopIteration
                return None

            rtc = self._nextrow()

            check_cancel_and_raise(rtc, self)

            if rtc == NO_MORE_ROWS:
                logger.debug("_mssql.MSSQLConnection.fetch_next_row(): NO MORE ROWS")
                self.clear_metadata()
                # 'rows_affected' is nonzero only after all records are read
                tds_socket = self.dbproc.tds_socket
                self._rows_affected = tds_socket.rows_affected
                if throw:
                    raise StopIteration
                return None

            return self.get_row(rtc)
        finally:
            logger.debug("_mssql.MSSQLConnection.fetch_next_row() END")

    def fetch_next_row_dict(self, throw):
        logger.debug("_mssql.MSSQLConnection.fetch_next_row_dict()")

        row_dict = {}
        row = self.fetch_next_row(throw)

        for col in xrange(1, self.num_columns + 1):
            name = self.column_names[col - 1]
            value = row[col - 1]

            # Add key by column name, only if the column has a name
            if name:
                row_dict[name] = value

            row_dict[col - 1] = value

        return row_dict

    def _sqlok(self):
        dbproc = self.dbproc
        return_code = SUCCEED
        logger.debug("dbsqlok()")
        #CHECK_CONN(FAIL);

        tds = dbproc.tds_socket
        # See what the next packet from the server is.
        # We want to skip any messages which are not processable. 
        # We're looking for a result token or a done token.
        #
        while True:
            #
            # If we hit an end token -- e.g. if the command
            # submitted returned no data (like an insert) -- then
            # we process the end token to extract the status code. 
            #
            logger.debug("dbsqlok() not done, calling tds_process_tokens()")

            tds_code, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

            #
            # The error flag may be set for any intervening DONEINPROC packet, in particular
            # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case. 
            #/
            if done_flags & TDS_DONE_ERROR:
                return_code = FAIL
            if tds_code == TDS_NO_MORE_RESULTS:
                return SUCCEED

            elif tds_code == TDS_SUCCESS:
                if result_type == TDS_ROWFMT_RESULT:
                    pass
                elif result_type == TDS_COMPUTEFMT_RESULT:
                    dbproc.dbresults_state = _DB_RES_RESULTSET_EMPTY;
                    logger.debug("dbsqlok() found result token")
                    return SUCCEED;
                elif result_type in (TDS_COMPUTE_RESULT, TDS_ROW_RESULT):
                    logger.debug("dbsqlok() found result token")
                    return SUCCEED;
                elif result_type == TDS_DONEINPROC_RESULT:
                    pass
                elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                    logger.debug("dbsqlok() end status is %s", prdbretcode(return_code))
                    if True:
                        if done_flags & TDS_DONE_ERROR:
                            if done_flags & TDS_DONE_MORE_RESULTS:
                                dbproc.dbresults_state = DB_RES_NEXT_RESULT
                            else:
                                dbproc.dbresults_state = DB_RES_NO_MORE_RESULTS

                        else:
                            logger.debug("dbsqlok() end status was success")
                            dbproc.dbresults_state = DB_RES_SUCCEED
                        return return_code
                    else:
                        retcode = FAIL if done_flags & TDS_DONE_ERROR else SUCCEED;
                        dbproc.dbresults_state = DB_RES_NEXT_RESULT if done_flags & TDS_DONE_MORE_RESULTS else _DB_RES_NO_MORE_RESULTS
                        logger.debug("dbsqlok: returning %s with %s (%#x)", 
                                        prdbretcode(retcode), prdbresults_state(dbproc.dbresults_state), done_flags)
                        if retcode == SUCCEED and (done_flags & TDS_DONE_MORE_RESULTS):
                            continue
                        return retcode
                else:
                    logger.debug('logic error: tds_process_tokens result_type %d', result_type);
            else:
                assert TDS_FAILED(tds_code)
                return FAIL
        return SUCCEED

    def format_and_run_query(self, query_string, params=None):
        """
        This is a helper function, which does most of the work needed by any
        execute_*() function. It returns NULL on error, None on success.
        """
        logger.debug("_mssql.MSSQLConnection.format_and_run_query() BEGIN")

        try:
            # Cancel any pending results
            self.cancel()

            if params:
                query_string = self.format_sql_command(query_string, params)

            logger.debug(query_string)

            rtc = SUCCEED
            if self.dbproc.tds_socket.state == TDS_PENDING:
                raise Exception('not checked')
                rc, result_type, _ = tds_process_tokens(tds, result_type, TDS_TOKEN_TRAILING)
                if rc != TDS_NO_MORE_RESULTS:
                    dbperror(self.dbproc, SYBERPND, 0)
                    rtc = FAIL

            # Execute the query
            if rtc == SUCCEED:
                tds_submit_query(self.dbproc.tds_socket, query_string)
                self.dbproc.envchange_rcv = 0
                self.dbproc.dbresults_state = DB_RES_INIT
                rtc = self._sqlok()
            check_cancel_and_raise(rtc, self)
        finally:
            logger.debug("_mssql.MSSQLConnection.format_and_run_query() END")

    def format_sql_command(self, format, params=None):
        logger.debug("_mssql.MSSQLConnection.format_sql_command()")
        return _substitute_params(format, params, self._charset)

    def get_header(self):
        """
        get_header() -- get the Python DB-API compliant header information.

        This method is infrastructure and doesn't need to be called by your
        code. It returns a list of 7-element tuples describing the current
        result header. Only name and DB-API compliant type is filled, rest
        of the data is None, as permitted by the specs.
        """
        logger.debug("_mssql.MSSQLConnection.get_header() BEGIN")
        try:
            self.get_result()

            if self.num_columns == 0:
                logger.debug("_mssql.MSSQLConnection.get_header(): num_columns == 0")
                return None

            header_tuple = []
            for col in xrange(1, self.num_columns + 1):
                col_name = self.column_names[col - 1]
                col_type = self.column_types[col - 1]
                header_tuple.append((col_name, col_type, None, None, None, None, None))
            return tuple(header_tuple)
        finally:
            logger.debug("_mssql.MSSQLConnection.get_header() END")

    def _start_results(self):
        dbproc = self.dbproc
        result_type = 0

        tds = dbproc.tds_socket

        logger.debug("dbresults: dbresults_state is %d (%s)\n", 
                                        dbproc.dbresults_state, prdbresults_state(dbproc.dbresults_state))
        if dbproc.dbresults_state == DB_RES_SUCCEED:
            dbproc.dbresults_state = DB_RES_NEXT_RESULT
            return SUCCEED
        elif dbproc.dbresults_state == DB_RES_RESULTSET_ROWS:
            dbperror(dbproc, SYBERPND, 0) # dbresults called while rows outstanding....
            return FAIL
        elif dbproc.dbresults_state == DB_RES_NO_MORE_RESULTS:
            return NO_MORE_RESULTS;

        while True:
            retcode, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

            logger.debug("dbresults() tds_process_tokens returned %d (%s),\n\t\t\tresult_type %s\n", 
                                            retcode, prretcode(retcode), prresult_type(result_type))

            if retcode == TDS_SUCCESS:
                if result_type == TDS_ROWFMT_RESULT:
                    #buffer_free(&dbproc->row_buf);
                    #buffer_alloc(dbproc);
                    dbproc.dbresults_state = DB_RES_RESULTSET_EMPTY

                elif result_type == TDS_COMPUTEFMT_RESULT:
                    pass

                elif result_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                    dbproc.dbresults_state = DB_RES_RESULTSET_ROWS
                    return SUCCEED

                elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                    logger.debug("dbresults(): dbresults_state is %d (%s)\n", 
                                    dbproc.dbresults_state, prdbresults_state(dbproc.dbresults_state))

                    # A done token signifies the end of a logical command.
                    # There are three possibilities:
                    # 1. Simple command with no result set, i.e. update, delete, insert
                    # 2. Command with result set but no rows
                    # 3. Command with result set and rows
                    #
                    if dbproc.dbresults_state in (DB_RES_INIT, DB_RES_NEXT_RESULT):
                        dbproc.dbresults_state = DB_RES_NEXT_RESULT
                        if done_flags & TDS_DONE_ERROR:
                            return FAIL

                    elif dbproc.dbresults_state in (DB_RES_RESULTSET_EMPTY, DB_RES_RESULTSET_ROWS):
                        dbproc.dbresults_state = DB_RES_NEXT_RESULT
                        return SUCCEED
                    else:
                        assert False

                elif result_type == TDS_DONEINPROC_RESULT:
                        #
                        # Return SUCCEED on a command within a stored procedure
                        # only if the command returned a result set. 
                        #
                        if dbproc.dbresults_state in (DB_RES_INIT, DB_RES_NEXT_RESULT):
                            dbproc.dbresults_state = DB_RES_NEXT_RESULT
                        elif dbproc.dbresults_state in (DB_RES_RESULTSET_EMPTY, DB_RES_RESULTSET_ROWS):
                            dbproc.dbresults_state = DB_RES_NEXT_RESULT
                            return SUCCEED;
                        elif dbproc.dbresults_state in (DB_RES_NO_MORE_RESULTS, DB_RES_SUCCEED):
                            pass

                elif result_type in (TDS_STATUS_RESULT, TDS_MSG_RESULT, TDS_DESCRIBE_RESULT, TDS_PARAM_RESULT):
                    pass
                else:
                    pass
            elif retcode == TDS_NO_MORE_RESULTS:
                dbproc.dbresults_state = DB_RES_NO_MORE_RESULTS
                return NO_MORE_RESULTS
            else:
                assert TDS_FAILED(retcode)
                dbproc.dbresults_state = DB_RES_INIT
                return FAIL

    def get_result(self):
        logger.debug("_mssql.MSSQLConnection.get_result() BEGIN")

        try:
            if self.last_dbresults:
                logger.debug("_mssql.MSSQLConnection.get_result(): last_dbresults == True, return None")
                return None

            self.clear_metadata()

            # Since python doesn't have a do/while loop do it this way
            while True:
                self.last_dbresults = self._start_results()
                self.num_columns = self.dbproc.tds_socket.res_info.num_cols if self.dbproc.tds_socket.res_info else 0
                if self.last_dbresults != SUCCEED or self.num_columns > 0:
                    break
            check_cancel_and_raise(self.last_dbresults, self)

            self._rows_affected = self.dbproc.tds_socket.rows_affected if self.dbproc.tds_socket.rows_affected != TDS_NO_COUNT else -1

            if self.last_dbresults == NO_MORE_RESULTS:
                self.num_columns = 0
                logger.debug("_mssql.MSSQLConnection.get_result(): NO_MORE_RESULTS, return None")
                return None

            self.num_columns = self.dbproc.tds_socket.res_info.num_cols

            logger.debug("_mssql.MSSQLConnection.get_result(): num_columns = %d", self.num_columns)

            column_names = list()
            column_types = list()

            for col in self.dbproc.tds_socket.res_info.columns:
                column_names.append(col.column_name)
                coltype = col.column_type
                column_types.append(get_api_coltype(coltype))

            self.column_names = tuple(column_names)
            self.column_types = tuple(column_types)
        finally:
            logger.debug("_mssql.MSSQLConnection.get_result() END")

    def get_row(self, row_info):
        dbproc = self.dbproc
        logger.debug("_mssql.MSSQLConnection.get_row()")

        record = tuple()

        for col in dbproc.tds_socket.res_info.columns:
            if is_blob_col(col):
                data = col.column_data.textvalue
            else:
                data = col.column_data
            col_type = col.column_type
            size = len(data)

            if data == None:
                record += (None,)
                continue

            logger.debug('Processing column %s,' \
                'Got data=%s, coltype=%d, len=%d', col.column_name,
                data, col_type, size)

            record += (self.convert_db_value(data, col_type, size),)
        return record

def get_last_msg_str(conn):
    return conn.last_msg_str

def get_last_msg_srv(conn):
    return conn.last_msg_srv

def get_last_msg_proc(conn):
    return conn.last_msg_proc

def get_last_msg_no(conn):
    return conn.last_msg_no

def get_last_msg_severity(conn):
    return conn.last_msg_severity

def get_last_msg_state(conn):
    return conn.last_msg_state

def get_last_msg_line(conn):
    return conn.last_msg_line

def maybe_raise_MSSQLDatabaseException(conn):

    if get_last_msg_severity(conn) < min_error_severity:
        return 0

    error_msg = get_last_msg_str(conn)
    if len(error_msg) == 0:
        error_msg = "Unknown error"

    ex = MSSQLDatabaseException((get_last_msg_no(conn), error_msg))
    ex.text = error_msg
    ex.srvname = get_last_msg_srv(conn)
    ex.procname = get_last_msg_proc(conn)
    ex.number = get_last_msg_no(conn)
    ex.severity = get_last_msg_severity(conn)
    ex.state = get_last_msg_state(conn)
    ex.line = get_last_msg_line(conn)
    db_cancel(conn)
    clr_err(conn)
    raise ex

def assert_connected(conn):
    logger.debug("_mssql.assert_connected()")
    if not conn.connected:
        raise MSSQLDriverException("Not connected to any MS SQL server")

def check_and_raise(rtc, conn):
    if rtc == FAIL:
        return maybe_raise_MSSQLDatabaseException(conn)
    elif get_last_msg_str(conn):
        return maybe_raise_MSSQLDatabaseException(conn)

def check_cancel_and_raise(rtc, conn):
    if rtc == FAIL:
        db_cancel(conn)
        return maybe_raise_MSSQLDatabaseException(conn)
    elif get_last_msg_str(conn):
        return maybe_raise_MSSQLDatabaseException(conn)

######################
## Helper Functions ##
######################
def get_api_coltype(coltype):
    if coltype in (SQLBIT, SQLINT1, SQLINT2, SQLINT4, SQLINT8, SQLINTN,
            SQLFLT4, SQLFLT8, SQLFLTN):
        return NUMBER
    elif coltype in (SQLMONEY, SQLMONEY4, SQLMONEYN, SQLNUMERIC,
            SQLDECIMAL):
        return DECIMAL
    elif coltype in (SQLDATETIME, SQLDATETIM4, SQLDATETIMN):
        return DATETIME
    elif coltype in (SQLVARCHAR, SQLCHAR, SQLTEXT):
        return STRING
    else:
        return BINARY
