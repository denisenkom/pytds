# vim: set fileencoding=utf8 :
"""DB-SIG compliant module for communicating with MS SQL servers"""

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = '0.4.0'

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

    @property
    def tds_version(self):
        '''
        Returns version of tds protocol that is being used by this connection
        '''
        return self.tds_socket.tds_version

    @property
    def product_version(self):
        '''
        Returns version of the server
        '''
        return self.tds_socket.product_version

    def _get_connection(self):
        if self.tds_socket.is_dead():
            # clear transaction
            self.tds_socket.tds72_transaction = '\x00\x00\x00\x00\x00\x00\x00\x00'
            tds_connect_and_login(self.tds_socket, self._login)
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
            cur = self.cursor()
            try:
                cur.execute(query)
            finally:
                cur.close()
            tds_submit_begin_tran(self.tds_socket)
            self._sqlok()
        return self.tds_socket

    def __init__(self, server, user, password,
            charset, database, appname, port, tds_version,
            as_dict, encryption_level, login_timeout, timeout):
        self._autocommit = False
        logger.debug("Connection.__init__()")
        self._charset = ''
        self.last_msg_no = 0
        self.last_msg_severity = 0
        self.last_msg_state = 0
        self.last_msg_str = ''
        self.last_msg_srv = ''
        self.last_msg_proc = ''
        self._as_dict = as_dict
        self._state = DB_RES_NO_MORE_RESULTS
        self.tds_socket = None

        # support MS methods of connecting locally
        instance = ""
        if "\\" in server:
            server, instance = server.split("\\")

        if server in (".", "(local)"):
            server = "localhost"

        self._login = login = tds_alloc_login(1)
        # set default values for loginrec
        login.library = "Python TDS Library"

        appname = appname or "pytds"

        login.encryption_level = encryption_level
        login.user_name = user or ''
        login.password = password or ''
        login.app = appname
        login.port = port
        if tds_version:
            login.tds_version = tds_version
        login.database = database

        # Set the character set name
        if charset:
            _charset = charset
            self._charset = _charset
            login.charset = self._charset

        # Connect to the server
        login.server_name = server
        login.instance_name = instance
        ctx = tds_alloc_context()
        ctx.msg_handler = self._msg_handler
        ctx.err_handler = self._err_handler
        ctx.int_handler = self._int_handler
        self.tds_socket = tds_alloc_socket(ctx, 512)
        self.tds_socket.chunk_handler = MemoryChunkedHandler()
        login.option_flag2 &= ~0x02 # we're not an ODBC driver
        tds_fix_login(login) # initialize from Environment variables

        login.connect_timeout = login_timeout
        login.query_timeout = timeout

    def autocommit(self, status):
        """
        Turn autocommit ON or OFF.
        """

        if status == self._autocommit:
            return

        self.cancel()
        if status:
            tds_submit_rollback(self.tds_socket, False)
        else:
            tds_submit_begin_tran(self.tds_socket)
        self._sqlok()
        self._autocommit = status

    def commit(self):
        """
        Commit transaction which is currently in progress.
        """

        if self._autocommit:
            return

        self.cancel()
        try:
            tds_submit_commit(self.tds_socket, True)
            self._sqlok()
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
        if self._autocommit:
            return

        if not self.tds_socket.is_dead():
            self.cancel()
            tds_submit_rollback(self.tds_socket, True)
            self._sqlok()

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
        self.clr_err()

        tds = self.tds_socket
        if not tds.is_dead():
            tds_send_cancel(tds)
            tds_process_cancel(tds)

    def close(self):
        """
        close() -- close connection to an MS SQL Server.

        This function tries to close the connection and free all memory used.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        logger.debug("MSSQLConnection.close()")
        self.clr_err()
        tds = self.tds_socket
        if tds is not None:
            tds_close_socket(tds)
            tds_free_socket(tds)

    def select_db(self, dbname):
        """
        select_db(dbname) -- Select the current database.

        This function selects the given database. An exception is raised on
        failure.
        """
        logger.debug("MSSQLConnection.select_db()")
        cur = self.cursor()
        try:
            cur.execute('use {0}'.format(tds_quote_id(self.tds_socket, dbname)))
        finally:
            cur.close()

    def _nextrow(self):
        logger.debug("_nextrow()")
        tds = self.tds_socket
        resinfo = tds.res_info
        if not resinfo or self._state != DB_RES_RESULTSET_ROWS:
            # no result set or result set empty (no rows)
            logger.debug("leaving _nextrow() returning NO_MORE_ROWS")
            return

        #
        # Try to get the self->row_buf.current item from the buffered rows, if any.  
        # Else read from the stream, unless the buffer is exhausted.  
        # If no rows are read, DBROWTYPE() will report NO_MORE_ROWS. 
        #/
        mask = TDS_STOPAT_ROWFMT|TDS_RETURN_DONE|TDS_RETURN_ROW|TDS_RETURN_COMPUTE

        # Get the row from the TDS stream.
        rc, res_type, _ = tds_process_tokens(tds, mask)
        if rc == TDS_SUCCESS:
            if res_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                # Add the row to the row buffer, whose capacity is always at least 1
                resinfo = tds.current_results
                #_, res_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
            else:
                self._state = DB_RES_NEXT_RESULT
        elif rc == TDS_NO_MORE_RESULTS:
            self._state = DB_RES_NEXT_RESULT
        else:
            raise Exception("unexpected result from tds_process_tokens")

    def _sqlok(self):
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
                maybe_raise_MSSQLDatabaseException(self)
                assert False
                raise Exception('FAIL')
            if tds_code == TDS_NO_MORE_RESULTS:
                return

            if result_type == TDS_ROWFMT_RESULT:
                pass
            elif result_type == TDS_COMPUTEFMT_RESULT:
                self._state = _DB_RES_RESULTSET_EMPTY;
                logger.debug("dbsqlok() found result token")
                break
            elif result_type in (TDS_COMPUTE_RESULT, TDS_ROW_RESULT):
                logger.debug("dbsqlok() found result token")
                break
            elif result_type == TDS_DONEINPROC_RESULT:
                pass
            elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                logger.debug("dbsqlok() end status is %s", prdbresults_state(self._state))
                if done_flags & TDS_DONE_ERROR:
                    if done_flags & TDS_DONE_MORE_RESULTS:
                        self._state = DB_RES_NEXT_RESULT
                    else:
                        self._state = DB_RES_NO_MORE_RESULTS

                else:
                    logger.debug("dbsqlok() end status was success")
                    self._state = DB_RES_SUCCEED
            else:
                logger.debug('logic error: tds_process_tokens result_type %d', result_type);

    def _start_results(self):
        result_type = 0

        tds = self.tds_socket

        logger.debug("_start_results begin: _state is %d (%s)\n", 
                                        self._state, prdbresults_state(self._state))
        if self._state == DB_RES_RESULTSET_ROWS:
            raise Exception('FAIL')
        elif self._state == DB_RES_NO_MORE_RESULTS:
            return

        while True:
            retcode, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

            logger.debug("_start_results() tds_process_tokens returned %d (%s),\n\t\t\tresult_type %s\n", 
                                            retcode, prretcode(retcode), prresult_type(result_type))

            if retcode == TDS_SUCCESS:
                if result_type == TDS_ROWFMT_RESULT:
                    self._state = DB_RES_RESULTSET_EMPTY

                elif result_type == TDS_COMPUTEFMT_RESULT:
                    pass

                elif result_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                    self._state = DB_RES_RESULTSET_ROWS
                    return

                elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                    logger.debug("_start_results() got done token _state is %d (%s)",
                                    self._state, prdbresults_state(self._state))

                    # A done token signifies the end of a logical command.
                    # There are three possibilities:
                    # 1. Simple command with no result set, i.e. update, delete, insert
                    # 2. Command with result set but no rows
                    # 3. Command with result set and rows
                    #
                    if self._state in (DB_RES_INIT, DB_RES_NEXT_RESULT):
                        self._state = DB_RES_NEXT_RESULT
                        if done_flags & TDS_DONE_ERROR:
                            raise Exception('FAIL')

                    elif self._state in (DB_RES_RESULTSET_EMPTY, DB_RES_RESULTSET_ROWS):
                        self._state = DB_RES_NEXT_RESULT
                        return
                    else:
                        assert False

                elif result_type == TDS_DONEINPROC_RESULT:
                        #
                        # Return SUCCEED on a command within a stored procedure
                        # only if the command returned a result set. 
                        #
                        if self._state in (DB_RES_INIT, DB_RES_NEXT_RESULT):
                            self._state = DB_RES_NEXT_RESULT
                        elif self._state in (DB_RES_RESULTSET_EMPTY, DB_RES_RESULTSET_ROWS):
                            self._state = DB_RES_NEXT_RESULT
                            return
                        elif self._state in (DB_RES_NO_MORE_RESULTS, DB_RES_SUCCEED):
                            pass

            elif retcode == TDS_NO_MORE_RESULTS:
                self._state = DB_RES_NO_MORE_RESULTS
                return
            else:
                self._state = DB_RES_INIT
                raise Exception('FAIL')

    def _getrow(self, throw):
        """
        Helper method used by fetchone and fetchmany to fetch and handle
        """
        if self._state == DB_RES_NO_MORE_RESULTS:
            logger.debug("MSSQLConnection.fetch_next_row(): NO MORE RESULTS")
            if throw:
                raise StopIteration
            return None

        self._nextrow()

        check_cancel_and_raise(self)

        if self._state != DB_RES_RESULTSET_ROWS:
            logger.debug("MSSQLConnection.fetch_next_row(): NO MORE ROWS")
            # 'rows_affected' is nonzero only after all records are read
            tds_socket = self.tds_socket
            self._rows_affected = tds_socket.rows_affected
            if throw:
                raise StopIteration
            return None

        cols = self.tds_socket.res_info.columns
        row = tuple(col.value for col in cols)
        if self.as_dict:
            row_dict = dict(enumerate(cols))
            row_dict.update(dict((col.column_name, col.value) for col in cols if col.column_name))
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
        if self._conn == None:
            raise InterfaceError('Cursor is closed.')
        return self._conn

    def __init__(self, conn):
        self._conn = conn
        self._batchsize = 1
        self._results = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

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
        logger.debug('callproc begin')
        self._results = None
        tds = self._conn._get_connection()
        if tds.state == TDS_PENDING:
            rc, result_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
            if rc != TDS_NO_MORE_RESULTS:
                raise InterfaceError('Results are still pending on connection')
        tds_submit_rpc(tds, procname, parameters)
        self._source._state = DB_RES_INIT
        self._source._sqlok()
        check_cancel_and_raise(self._source)
        logger.debug('callproc end')

    def get_proc_return_status(self):
        self._get_results()
        tds = self._conn.tds_socket
        if not tds.has_status:
            tds_process_tokens(tds, TDS_RETURN_PROC)
        return tds.ret_status if tds.has_status else None

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        self._conn.cancel()
        self._conn = None

    def execute(self, operation, params=()):
        self._results = None
        tds = self._conn._get_connection()
        if tds.state == TDS_PENDING:
            rc, result_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
            if rc != TDS_NO_MORE_RESULTS:
                raise InterfaceError('Results are still pending on connection')

        # Execute the query
        if params:
            if isinstance(params, (list, tuple)):
                names = tuple('@P{0}'.format(n) for n in range(len(params)))
                if len(names) == 1:
                    operation = operation % names[0]
                else:
                    operation = operation % names
                params = dict(zip(names, params))
            elif isinstance(params, dict):
                # prepend names with @
                rename = dict((name, '@{0}'.format(name)) for name in params.keys())
                params = dict(('@{0}'.format(name), value) for name, value in params.items())
                operation = operation % rename
            logger.debug('converted query: {0}'.format(operation))
            logger.debug('params: {0}'.format(params))
        tds_submit_query(tds, operation, params)
        self._conn._state = DB_RES_INIT
        self._conn._sqlok()
        check_cancel_and_raise(self._conn)

    def executemany(self, operation, params_seq):
        self._results = None
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
        self._results = None
        self._conn.clr_err()

        self._conn._nextrow()
        check_cancel_and_raise(self._conn)

        while self._conn._state == DB_RES_RESULTSET_ROWS:
            self._conn._nextrow()
            check_cancel_and_raise(self._conn)
        self._get_results()
        return None if self._conn._state == DB_RES_NO_MORE_RESULTS else True

    def _get_results(self):
        if not self._results:
            tds = self._conn.tds_socket
            self._conn._start_results()
            check_cancel_and_raise(self._conn)
            self._rows_affected = tds.rows_affected if tds.rows_affected != TDS_NO_COUNT else -1
            if self._conn._state == DB_RES_NO_MORE_RESULTS:
                descr = None
            else:
                header_tuple = []
                for col in tds.res_info.columns:
                    coltype = get_api_coltype(col.column_type)
                    header_tuple.append((col.column_name, coltype, None, None, None, None, None))
                descr = tuple(header_tuple)
            logger.debug('_get_results set description: %s', descr)
            self._results = {'description': descr}
        return self._results

    @property
    def rowcount(self):
        self._get_results()
        return self._rows_affected

    @property
    def description(self):
        return self._get_results()['description']

    def fetchone(self):
        self._get_results()
        return self._conn._getrow(throw=False)

    def fetchmany(self, size=None):
        self._get_results()
        if size == None:
            size = self._batchsize
        self.batchsize = size

        rows = []
        for i in xrange(size):
            row = self._conn._getrow(throw=False)
            if not row:
                break
            rows.append(row)
        return rows

    def fetchall(self):
        self._get_results()
        rows = []
        while True:
            row = self._conn._getrow(throw=False)
            if not row:
                break
            rows.append(row)
        return rows

    def next(self):
        self._get_results()
        row = self._conn._getrow(throw=True)
        return row

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

def connect(server='.', database='', user='', password='', timeout=0,
        login_timeout=60, charset=None, as_dict=False,
        host='', appname=None, port=None, tds_version=TDS74,
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

    conn = Connection(server, user, password, charset, database,
        appname, port, tds_version=tds_version, as_dict=as_dict, login_timeout=login_timeout,
        timeout=timeout, encryption_level=encryption_level)

    return conn

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

    msg_no = get_last_msg_no(conn)
    if msg_no in prog_errors:
        ex = ProgrammingError(error_msg)
    elif msg_no in integrity_errors:
        ex = IntegrityError(error_msg)
    else:
        ex = OperationalError(error_msg)
    ex.msg_no = msg_no
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

def check_cancel_and_raise(conn):
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
