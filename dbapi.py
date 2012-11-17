# vim: set fileencoding=utf8 :
"""DB-SIG compliant module for communicating with MS SQL servers"""

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = '1.0.0'

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

# comliant with DB SIG 2.0
apilevel = '2.0'

# module may be shared, but not connections
threadsafety = 1

# this module uses extended python format codes
paramstyle = 'pyformat'

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
    pass

class DataError(Error):
    pass

class OperationalError(DatabaseError):
    pass

class IntegrityError(DatabaseError):
    pass

class InternalError(DatabaseError):
    pass

class ProgrammingError(DatabaseError):
    pass

class NotSupportedError(DatabaseError):
    pass

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
    if retcode == TDS_SUCCESS or retcode is None:return "TDS_SUCCESS"
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


class MemoryChunkedHandler(object):
    def begin(self, column, size):
        logger.debug('MemoryChunkedHandler.begin(sz=%d)', size)
        self.size = size
        self.sio = StringIO()
    def new_chunk(self, val):
        logger.debug('MemoryChunkedHandler.new_chunk(sz=%d)', len(val))
        self.sio.write(val)
    def end(self):
        return self.sio.getvalue()


min_error_severity = 6
######################
## Connection class ##
######################
class Connection(object):
    @property
    def as_dict(self):
        """
        Instructs all cursors this connection creates to return results
        as a dictionary rather than a tuple.
        """
        return self._as_dict

    @as_dict.setter
    def as_dict(self, value):
        self._as_dict = value

    @property
    def autocommit_state(self):
        """
        The current state of autocommit on the connection.
        """
        return self._autocommit

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

    @property
    def chunk_handler(self):
        '''
        Returns current chunk handler
        Default is MemoryChunkedHandler()
        '''
        return self.tds_socket.chunk_handler

    @chunk_handler.setter
    def chunk_handler_set(self, value):
        self.tds_socket.chunk_handler = value

    def __init__(self, server, user, password,
            charset, database, appname, port, tds_version,
            as_dict, encryption_level, login_timeout, timeout):
        self.conn = self
        self._autocommit = False
        logger.debug("Connection.__init__()")
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
        self._as_dict = as_dict

        # support MS methods of connecting locally
        instance = ""
        if "\\" in server:
            server, instance = server.split("\\")

        if server in (".", "(local)"):
            server = "localhost"

        server = server + "\\" + instance if instance else server

        login = tds_alloc_login(1)
        # set default values for loginrec
        login.library = "Python TDS Library"

        appname = appname or "pytds"

        login.encryption_level = encryption_level
        login.user_name = user
        login.password = password
        login.app = appname
        if tds_version:
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
            self.msdblib = msdblib
            tds_set_server(login, server)
            ctx = tds_alloc_context()
            ctx.msg_handler = self._msg_handler
            ctx.err_handler = self._err_handler
            ctx.int_handler = self._int_handler
            self.tds_socket = tds_alloc_socket(ctx, 512)
            self.tds_socket.chunk_handler = MemoryChunkedHandler()
            self.tds_socket.env_chg_func = self._db_env_chg
            self.envchange_rcv = 0
            self.dbcurdb = ''
            self.servcharset = ''
            login.option_flag2 &= ~0x02 # we're not an ODBC driver
            tds_fix_login(login) # initialize from Environment variables

            login.connect_timeout = login_timeout
            login.query_timeout = timeout

            tds_connect_and_login(self.tds_socket, login)
        except Exception as e:
            logger.exception("MSSQLConnection.__init__() connection failed")
            maybe_raise_MSSQLDatabaseException(self)
            raise InterfaceError("Connection to the database failed: " + unicode(e))

        self._connected = 1

        logger.debug("MSSQLConnection.__init__() -> dbcmd() setting connection values")
        # Set some connection properties to some reasonable values
        # textsize - http://msdn.microsoft.com/en-us/library/aa259190%28v=sql.80%29.aspx
        query = '''
            SET ARITHABORT ON;
            SET CONCAT_NULL_YIELDS_NULL ON;
            SET ANSI_NULLS ON;
            SET ANSI_NULL_DFLT_ON ON;
            SET ANSI_PADDING ON;
            SET ANSI_WARNINGS ON;
            SET ANSI_NULL_DFLT_ON ON;
            SET CURSOR_CLOSE_ON_COMMIT ON;
            SET QUOTED_IDENTIFIER ON;
            SET TEXTSIZE 2147483647;
        '''
        self.execute_non_query(query)
        try:
            self.execute_non_query('BEGIN TRAN')
        except Exception, e:
            raise OperationalError('Cannot start transaction: ' + str(e[0]))

    def autocommit(self, status):
        """
        Turn autocommit ON or OFF.
        """

        if status == self._autocommit:
            return

        tran_type = 'ROLLBACK' if status else 'BEGIN'
        self.execute_non_query('%s TRAN' % tran_type)
        self._autocommit = status

    def commit(self):
        """
        Commit transaction which is currently in progress.
        """

        if self._autocommit == True:
            return

        try:
            self.execute_non_query('COMMIT TRAN; BEGIN TRAN')
        except Exception, e:
            raise OperationalError('Cannot commit transaction: ' + str(e[0]))

    def cursor(self):
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        return Cursor(self)

    def rollback(self):
        """
        Roll back transaction which is currently in progress.
        """
        if self._autocommit == True:
            return

        try:
            self.execute_non_query('ROLLBACK TRAN')
        except MSSQLException, e:
            # PEP 249 indicates that we have contract with the user that we will
            # always have a transaction in place if autocommit is False.
            # Therefore, it seems logical to ignore this exception since it
            # indicates a situation we shouldn't ever encounter anyway.  However,
            # it can happen when an error is severe enough to cause a
            # "batch-abort".  In that case, SQL Server *implicitly* rolls back
            # the transaction for us (how helpful!).  But there doesn't seem
            # to be any way for us to know if an error is severe enough to cause
            # a batch abort:
            #   http://stackoverflow.com/questions/5877162/why-does-microsoft-sql-server-implicitly-rollback-when-a-create-statement-fails
            #
            # the alternative is to do 'select @@trancount' before each rollback
            # but that is slower and doesn't seem to offer any benefit.
            if 'The ROLLBACK TRANSACTION request has no corresponding BEGIN TRANSACTION' not in str(e):
                raise
        try:
            self.execute_non_query('BEGIN TRAN')
        except Exception, e:
            raise OperationalError('Cannot begin transaction: ' + str(e[0]))

    def clr_err(self):
        self.last_msg_no = 0
        self.last_msg_severity = 0
        self.last_msg_state = 0

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

        self.envchange_rcv |= (1 << (type - 1))
        if type == TDS_ENV_DATABASE:
            self.dbcurdb = newval
        elif type == TDS_ENV_CHARSET:
            self.servcharset = newval

    def __del__(self):
        logger.debug("MSSQLConnection.__del__()")
        self.close()

    def cancel(self):
        """
        cancel() -- cancel all pending results.

        This function cancels all pending results from the last SQL operation.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        logger.debug("MSSQLConnection.cancel()")
        assert_connected(self)
        self.clr_err()

        tds_send_cancel(self.tds_socket)
        tds_process_cancel(self.tds_socket)
        self.clear_metadata()

    def clear_metadata(self):
        logger.debug("MSSQLConnection.clear_metadata()")
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
        logger.debug("MSSQLConnection.close()")
        if self == None:
            return None

        if not self._connected:
            return None

        self.clr_err()

        tds = self.tds_socket
        if tds:
            tds_free_socket(tds)

        self._connected = 0

    def convert_db_value(self, data, type, length):
        logger.debug("MSSQLConnection.convert_db_value()")

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

            #len = dbconvert(self, type, data, -1, SQLCHAR,
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
        logger.debug("MSSQLConnection.select_db()")
        self.execute_non_query('use {0}'.format(tds_quote_id(self.tds_socket, dbname)))

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
        logger.debug("MSSQLConnection.execute_non_query() BEGIN")

        self.format_and_run_query(query_string, params)
        # getting results
        self._rows_affected = self.tds_socket.rows_affected
        # discard results
        self.cancel()
        logger.debug("MSSQLConnection.execute_non_query() END")

    def _nextrow(self):
        result = FAIL
        logger.debug("_nextrow()")
        tds = self.tds_socket
        resinfo = tds.res_info
        if not resinfo or self.dbresults_state != DB_RES_RESULTSET_ROWS:
            # no result set or result set empty (no rows)
            logger.debug("leaving _nextrow() returning %d (NO_MORE_ROWS)", NO_MORE_ROWS)
            self.row_type = NO_MORE_ROWS
            return NO_MORE_ROWS

        #
        # Try to get the self->row_buf.current item from the buffered rows, if any.  
        # Else read from the stream, unless the buffer is exhausted.  
        # If no rows are read, DBROWTYPE() will report NO_MORE_ROWS. 
        #/
        self.row_type = NO_MORE_ROWS
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
                result = self.row_type = REG_ROW if res_type == TDS_ROW_RESULT else computeid
                #_, res_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
            else:
                self.dbresults_state = DB_RES_NEXT_RESULT
                result = NO_MORE_ROWS
        elif rc == TDS_NO_MORE_RESULTS:
            self.dbresults_state = DB_RES_NEXT_RESULT
            result = NO_MORE_ROWS
        else:
            raise Exception("unexpected result from tds_process_tokens")

        if res_type == TDS_COMPUTE_RESULT:
            logger.debug("leaving _nextrow() returning compute_id %d\n", result)
        else:
            logger.debug("leaving _nextrow() returning %s\n", prdbretcode(result))
        return result

    def nextresult(self):
        """
        nextresult() -- move to the next result, skipping all pending rows.

        This method fetches and discards any rows remaining from the current
        resultset, then it advances to the next (if any) resultset. Returns
        True if the next resultset is available, otherwise None.
        """

        logger.debug("Connection.nextresult()")

        assert_connected(self)
        self.clr_err()

        rtc = self._nextrow()
        check_cancel_and_raise(rtc, self)

        while rtc != NO_MORE_ROWS:
            rtc = self._nextrow()
            check_cancel_and_raise(rtc, self)

        self.last_dbresults = 0
        self.get_result()

        if self.last_dbresults != NO_MORE_RESULTS:
            return True

    def _sqlok(self):
        return_code = SUCCEED
        logger.debug("dbsqlok()")
        #CHECK_CONN(FAIL);

        tds = self.tds_socket
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
                    self.dbresults_state = _DB_RES_RESULTSET_EMPTY;
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
                                self.dbresults_state = DB_RES_NEXT_RESULT
                            else:
                                self.dbresults_state = DB_RES_NO_MORE_RESULTS

                        else:
                            logger.debug("dbsqlok() end status was success")
                            self.dbresults_state = DB_RES_SUCCEED
                        return return_code
                    else:
                        retcode = FAIL if done_flags & TDS_DONE_ERROR else SUCCEED;
                        self.dbresults_state = DB_RES_NEXT_RESULT if done_flags & TDS_DONE_MORE_RESULTS else _DB_RES_NO_MORE_RESULTS
                        logger.debug("dbsqlok: returning %s with %s (%#x)", 
                                        prdbretcode(retcode), prdbresults_state(self.dbresults_state), done_flags)
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
        logger.debug("MSSQLConnection.format_and_run_query() BEGIN")

        try:
            # Cancel any pending results
            self.cancel()

            logger.debug(query_string)

            rtc = SUCCEED
            if self.tds_socket.state == TDS_PENDING:
                raise Exception('not checked')
                rc, result_type, _ = tds_process_tokens(tds, result_type, TDS_TOKEN_TRAILING)
                if rc != TDS_NO_MORE_RESULTS:
                    dbperror(self, SYBERPND, 0)
                    rtc = FAIL

            # Execute the query
            if rtc == SUCCEED:
                if params:
                    if isinstance(params, (list, tuple)):
                        names = tuple('@P{0}'.format(n) for n in range(len(params)))
                        if len(names) == 1:
                            query_string = query_string % names[0]
                        else:
                            query_string = query_string % names
                        params = dict(zip(names, params))
                    elif isinstance(params, dict):
                        # prepend names with @
                        rename = dict((name, '@{0}'.format(name)) for name in params.keys())
                        params = dict(('@{0}'.format(name), value) for name, value in params.items())
                        query_string = query_string % rename
                    logger.debug('converted query: {0}'.format(query_string))
                    logger.debug('params: {0}'.format(params))
                tds_submit_query(self.tds_socket, query_string, params)
                self.envchange_rcv = 0
                self.dbresults_state = DB_RES_INIT
                rtc = self._sqlok()
            check_cancel_and_raise(rtc, self)
        finally:
            logger.debug("MSSQLConnection.format_and_run_query() END")

    def format_sql_command(self, format, params=None):
        logger.debug("MSSQLConnection.format_sql_command()")
        return _substitute_params(format, params, self._charset)

    def get_header(self):
        """
        get_header() -- get the Python DB-API compliant header information.

        This method is infrastructure and doesn't need to be called by your
        code. It returns a list of 7-element tuples describing the current
        result header. Only name and DB-API compliant type is filled, rest
        of the data is None, as permitted by the specs.
        """
        logger.debug("MSSQLConnection.get_header() BEGIN")
        try:
            self.get_result()

            if self.num_columns == 0:
                logger.debug("MSSQLConnection.get_header(): num_columns == 0")
                return None

            header_tuple = []
            for col in xrange(1, self.num_columns + 1):
                col_name = self.column_names[col - 1]
                col_type = self.column_types[col - 1]
                header_tuple.append((col_name, col_type, None, None, None, None, None))
            return tuple(header_tuple)
        finally:
            logger.debug("MSSQLConnection.get_header() END")

    def _start_results(self):
        result_type = 0

        tds = self.tds_socket

        logger.debug("dbresults: dbresults_state is %d (%s)\n", 
                                        self.dbresults_state, prdbresults_state(self.dbresults_state))
        if self.dbresults_state == DB_RES_SUCCEED:
            self.dbresults_state = DB_RES_NEXT_RESULT
            return SUCCEED
        elif self.dbresults_state == DB_RES_RESULTSET_ROWS:
            dbperror(self, SYBERPND, 0) # dbresults called while rows outstanding....
            return FAIL
        elif self.dbresults_state == DB_RES_NO_MORE_RESULTS:
            return NO_MORE_RESULTS;

        while True:
            retcode, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

            logger.debug("dbresults() tds_process_tokens returned %d (%s),\n\t\t\tresult_type %s\n", 
                                            retcode, prretcode(retcode), prresult_type(result_type))

            if retcode == TDS_SUCCESS:
                if result_type == TDS_ROWFMT_RESULT:
                    self.dbresults_state = DB_RES_RESULTSET_EMPTY

                elif result_type == TDS_COMPUTEFMT_RESULT:
                    pass

                elif result_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                    self.dbresults_state = DB_RES_RESULTSET_ROWS
                    return SUCCEED

                elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                    logger.debug("dbresults(): dbresults_state is %d (%s)\n", 
                                    self.dbresults_state, prdbresults_state(self.dbresults_state))

                    # A done token signifies the end of a logical command.
                    # There are three possibilities:
                    # 1. Simple command with no result set, i.e. update, delete, insert
                    # 2. Command with result set but no rows
                    # 3. Command with result set and rows
                    #
                    if self.dbresults_state in (DB_RES_INIT, DB_RES_NEXT_RESULT):
                        self.dbresults_state = DB_RES_NEXT_RESULT
                        if done_flags & TDS_DONE_ERROR:
                            return FAIL

                    elif self.dbresults_state in (DB_RES_RESULTSET_EMPTY, DB_RES_RESULTSET_ROWS):
                        self.dbresults_state = DB_RES_NEXT_RESULT
                        return SUCCEED
                    else:
                        assert False

                elif result_type == TDS_DONEINPROC_RESULT:
                        #
                        # Return SUCCEED on a command within a stored procedure
                        # only if the command returned a result set. 
                        #
                        if self.dbresults_state in (DB_RES_INIT, DB_RES_NEXT_RESULT):
                            self.dbresults_state = DB_RES_NEXT_RESULT
                        elif self.dbresults_state in (DB_RES_RESULTSET_EMPTY, DB_RES_RESULTSET_ROWS):
                            self.dbresults_state = DB_RES_NEXT_RESULT
                            return SUCCEED;
                        elif self.dbresults_state in (DB_RES_NO_MORE_RESULTS, DB_RES_SUCCEED):
                            pass

                elif result_type in (TDS_STATUS_RESULT, TDS_MSG_RESULT, TDS_DESCRIBE_RESULT, TDS_PARAM_RESULT):
                    pass
                else:
                    pass
            elif retcode == TDS_NO_MORE_RESULTS:
                self.dbresults_state = DB_RES_NO_MORE_RESULTS
                return NO_MORE_RESULTS
            else:
                assert TDS_FAILED(retcode)
                self.dbresults_state = DB_RES_INIT
                return FAIL

    def get_result(self):
        logger.debug("MSSQLConnection.get_result() BEGIN")

        try:
            if self.last_dbresults:
                logger.debug("MSSQLConnection.get_result(): last_dbresults == True, return None")
                return None

            self.clear_metadata()

            # Since python doesn't have a do/while loop do it this way
            while True:
                self.last_dbresults = self._start_results()
                self.num_columns = self.tds_socket.res_info.num_cols if self.tds_socket.res_info else 0
                if self.last_dbresults != SUCCEED or self.num_columns > 0:
                    break
            check_cancel_and_raise(self.last_dbresults, self)

            self._rows_affected = self.tds_socket.rows_affected if self.tds_socket.rows_affected != TDS_NO_COUNT else -1

            if self.last_dbresults == NO_MORE_RESULTS:
                self.num_columns = 0
                logger.debug("MSSQLConnection.get_result(): NO_MORE_RESULTS, return None")
                return None

            self.num_columns = self.tds_socket.res_info.num_cols

            logger.debug("MSSQLConnection.get_result(): num_columns = %d", self.num_columns)

            column_names = list()
            column_types = list()

            for col in self.tds_socket.res_info.columns:
                column_names.append(col.column_name)
                coltype = col.column_type
                column_types.append(get_api_coltype(coltype))

            self.column_names = tuple(column_names)
            self.column_types = tuple(column_types)
        finally:
            logger.debug("MSSQLConnection.get_result() END")

    def _getrow(self, throw):
        """
        Helper method used by fetchone and fetchmany to fetch and handle
        """
        assert_connected(self.conn)
        self.clr_err()
        self.get_result()

        if self.last_dbresults == NO_MORE_RESULTS:
            logger.debug("MSSQLConnection.fetch_next_row(): NO MORE RESULTS")
            self.clear_metadata()
            if throw:
                raise StopIteration
            return None

        rtc = self._nextrow()

        check_cancel_and_raise(rtc, self)

        if rtc == NO_MORE_ROWS:
            logger.debug("MSSQLConnection.fetch_next_row(): NO MORE ROWS")
            self.clear_metadata()
            # 'rows_affected' is nonzero only after all records are read
            tds_socket = self.tds_socket
            self._rows_affected = tds_socket.rows_affected
            if throw:
                raise StopIteration
            return None

        row = list()

        for col in self.tds_socket.res_info.columns:
            if is_blob_col(col):
                data = col.column_data.textvalue
            else:
                data = col.column_data
            col_type = col.column_type
            size = len(data)

            if data == None:
                row.append(None)
                continue

            logger.debug('Processing column %s,' \
                'Got data=%s, coltype=%d, len=%d', col.column_name,
                data, col_type, size)

            row.append(self.convert_db_value(data, col_type, size))
        row = tuple(row)
        if self.as_dict:
            row_dict = {}

            for i, col in enumerate(self.tds_socket.res_into.columns):
                name = col.column_name
                value = row[i]

                # Add key by column name, only if the column has a name
                if name:
                    row_dict[name] = value

                row_dict[i] = value

            row = row_dict
        return row

##################
## Cursor class ##
##################
class Cursor(object):
    """
    This class represents a database cursor, which is used to issue queries
    and fetch results from a database connection.
    """
    @property
    def _source(self):
        if self.conn == None:
            raise InterfaceError('Cursor is closed.')
        return self.conn

    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._batchsize = 1
        self._returnvalue = None

    def __iter__(self):
        """
        Return self to make cursors compatibile with Python iteration
        protocol.
        """
        return self

    def callproc(self, procname, parameters=()):
        """
        Call a stored procedure with the given name.

        :param procname: The name of the procedure to call
        :type procname: str
        :keyword parameters: The optional parameters for the procedure
        :type parameters: sequence
        """
        self._returnvalue = None
        tds = self._source.tds_socket
        tds_submit_rpc(tds, procname, parameters)
        self._source.last_dbresults = 0
        self._source.dbresults_state = DB_RES_INIT
        rtc = self._source._sqlok()
        check_cancel_and_raise(rtc, self._source)

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        self.conn = None
        self.description = None

    def execute(self, operation, params=()):
        self.description = None

        try:
            self._source.format_and_run_query(operation, params)
            self._source.get_result()
            self.description = self._source.get_header()

        except MSSQLDatabaseException, e:
            if e.number in prog_errors:
                raise ProgrammingError, e[0]
            if e.number in integrity_errors:
                raise IntegrityError, e[0]
            raise OperationalError, e[0]
        except MSSQLDriverException, e:
            raise InterfaceError, e[0]

    def executemany(self, operation, params_seq):
        self.description = None
        for params in params_seq:
            self.execute(operation, params)
            # support correct rowcount across multiple executes

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
        self.execute(query_string, params)
        row = self.fetchone()
        if not row:
            return None
        return row[0]

    def nextset(self):
        try:
            if not self._source.nextresult():
                return None
            self.description = self._source.get_header()
            return 1

        except MSSQLDatabaseException, e:
            raise OperationalError, e[0]
        except MSSQLDriverException, e:
            raise InterfaceError, e[0]

        return None

    def fetchone(self):
        if self.description is None:
            raise OperationalError('Statement not executed or executed statement has no resultset')

        try:
            return self.conn._getrow(throw=False)
        except MSSQLDatabaseException, e:
            raise OperationalError, e[0]
        except MSSQLDriverException, e:
            raise InterfaceError, e[0]

    def fetchmany(self, size=None):
        if self.description is None:
            raise OperationalError('Statement not executed or executed statement has no resultset')

        if size == None:
            size = self._batchsize
        self.batchsize = size

        try:
            rows = []
            for i in xrange(size):
                row = self.conn._getrow(throw=False)
                if not row:
                    break
                rows.append(row)
            return rows
        except MSSQLDatabaseException, e:
            raise OperationalError, e[0]
        except MSSQLDriverException, e:
            raise InterfaceError, e[0]

    def fetchall(self):
        if self.description is None:
            raise OperationalError('Statement not executed or executed statement has no resultset')

        try:
            rows = [row for row in self]
            return rows
        except MSSQLDatabaseException, e:
            raise OperationalError, e[0]
        except MSSQLDriverException, e:
            raise InterfaceError, e[0]

    def next(self):
        try:
            row = self.conn._getrow(throw=True)
            return row

        except MSSQLDatabaseException, e:
            raise OperationalError, e[0]
        except MSSQLDriverException, e:
            raise InterfaceError, e[0]

    def setinputsizes(self, sizes=None):
        """
        This method does nothing, as permitted by DB-API specification.
        """
        pass

    def setoutputsize(self, size=None, column=0):
        """
        This method does nothing, as permitted by DB-API specification.
        """
        pass

def connect(server='.', user='', password='', database='', timeout=0,
        login_timeout=60, charset=None, as_dict=False,
        host='', appname=None, port='1433', tds_version='',
        encryption_level=TDS_ENCRYPTION_OFF):
    """
    Constructor for creating a connection to the database. Returns a
    Connection object.

    :param server: database host
    :type server: string
    :param user: database user to connect as
    :type user: string
    :param password: user's password
    :type password: string
    :param database: the database to initially connect to
    :type database: string
    :param timeout: query timeout in seconds, default 0 (no timeout)
    :type timeout: int
    :param login_timeout: timeout for connection and login in seconds, default 60
    :type login_timeout: int
    :param charset: character set with which to connect to the database
    :type charset: string
    :keyword as_dict: whether rows should be returned as dictionaries instead of tuples.
    :type as_dict: boolean
    :keyword appname: Set the application name to use for the connection
    :type appname: string
    :keyword port: the TCP port to use to connect to the server
    :type appname: string
    """

    # set the login timeout
    try:
        login_timeout = int(login_timeout)
    except ValueError:
        login_timeout = 0

    # default query timeout
    try:
        timeout = int(timeout)
    except ValueError:
        timeout = 0

    if host:
        server = host

    try:
        conn = Connection(server, user, password, charset, database,
            appname, port, tds_version=tds_version, as_dict=as_dict, login_timeout=login_timeout,
            timeout=timeout, encryption_level=encryption_level)

    except MSSQLDatabaseException, e:
        raise OperationalError(e[0])

    except MSSQLDriverException, e:
        raise InterfaceError(e[0])

    return conn


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
    conn.cancel()
    conn.clr_err()
    raise ex

def assert_connected(conn):
    logger.debug("assert_connected()")
    if not conn.connected:
        raise MSSQLDriverException("Not connected to any MS SQL server")

def check_and_raise(rtc, conn):
    if rtc == FAIL:
        return maybe_raise_MSSQLDatabaseException(conn)
    elif get_last_msg_str(conn):
        return maybe_raise_MSSQLDatabaseException(conn)

def check_cancel_and_raise(rtc, conn):
    if rtc == FAIL:
        conn.cancel()
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
