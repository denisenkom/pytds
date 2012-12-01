# vim: set fileencoding=utf8 :
"""DB-SIG compliant module for communicating with MS SQL servers"""

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = '0.5.0'

import logging
import decimal
import re
from tds import *
from login import *
from query import *

logger = logging.getLogger(__name__)

# comliant with DB SIG 2.0
apilevel = '2.0'

# module may be shared, but not connections
threadsafety = 1

# this module uses extended python format codes
paramstyle = 'pyformat'

DB_RES_INIT            = 0
DB_RES_RESULTSET_EMPTY = 1
DB_RES_RESULTSET_ROWS  = 2
DB_RES_NEXT_RESULT     = 3
DB_RES_NO_MORE_RESULTS = 4
DB_RES_SUCCEED         = 5

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

class _TdsLogin:
    pass

######################
## Connection class ##
######################
class _Connection(object):
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
        tds = self._get_connection()
        return tds.tds_version

    @property
    def product_version(self):
        '''
        Returns version of the server
        '''
        return self.tds_socket.product_version

    def _get_connection(self):
        if self._closed:
            raise Error('Connection is closed')
        if self.tds_socket.is_dead():
            self.tds_socket.tds72_transaction = None
            tds_connect_and_login(self.tds_socket, self._login)
            self._try_activate_cursor(None)
            if not self._autocommit:
                tds_submit_query(self.tds_socket, 'set implicit_transactions on')
            self._sqlok()
        return self.tds_socket

    def __init__(self, login, as_dict, autocommit):
        self._login = login
        self._as_dict = as_dict
        self._autocommit = autocommit
        self._state = DB_RES_NO_MORE_RESULTS
        self._closed = False
        self._active_cursor = None
        from tds import _TdsSocket
        self.tds_socket = _TdsSocket(login.blocksize)
        self.tds_socket.chunk_handler = MemoryChunkedHandler()

    def commit(self):
        """
        Commit transaction which is currently in progress.
        """
        if self._autocommit:
            return

        tds = self._get_connection()
        if not tds.tds72_transaction:
            return

        try:
            self._try_activate_cursor(None)
            tds_submit_commit(tds, True)
            self._sqlok()
            while self._nextset(None):
                pass
        except Exception, e:
            raise OperationalError('Cannot commit transaction: ' + str(e[0]))

    def cursor(self):
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        return _Cursor(self)

    def rollback(self):
        """
        Roll back transaction which is currently in progress.
        """
        if self._autocommit:
            return

        if not self.tds_socket.is_dead():
            tds = self._get_connection()
            self.cancel()
            self._active_cursor = None
            tds_submit_rollback(tds, True)
            self._sqlok()
            while self._nextset(None):
                pass

    def __del__(self):
        logger.debug("MSSQLConnection.__del__()")
        if not self._closed:
            self.close()

    def cancel(self):
        """
        cancel() -- cancel all pending results.

        This function cancels all pending results from the last SQL operation.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        logger.debug("MSSQLConnection.cancel()")
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
        if self._closed:
            raise Error('Connection closed')
        self._closed = True
        tds = self.tds_socket
        if tds is not None:
            tds.close()
            self.tds_socket = None

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
        rc, res_type, done_flags = tds_process_tokens(tds, mask)
        if done_flags & TDS_DONE_ERROR:
            raise_db_exception(tds)
            assert False
            raise Exception('FAIL')
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
        #
        # If we hit an end token -- e.g. if the command
        # submitted returned no data (like an insert) -- then
        # we process the end token to extract the status code. 
        #
        logger.debug("dbsqlok() not done, calling tds_process_tokens()")
        while True:
            tds_code, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

            #
            # The error flag may be set for any intervening DONEINPROC packet, in particular
            # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case. 
            #/
            if done_flags & TDS_DONE_ERROR:
                raise_db_exception(tds)
                assert False
                raise Exception('FAIL')
            if result_type == TDS_ROWFMT_RESULT:
                self._state = DB_RES_RESULTSET_ROWS
                break
            elif result_type == TDS_DONEINPROC_RESULT:
                if not done_flags & TDS_DONE_COUNT:
                    # skip results that don't event have rowcount
                    continue
                self._state = DB_RES_RESULTSET_EMPTY
                break
            elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                if done_flags & TDS_DONE_MORE_RESULTS:
                    self._state = DB_RES_NEXT_RESULT
                else:
                    self._state = DB_RES_NO_MORE_RESULTS
                break
            elif result_type == TDS_STATUS_RESULT:
                continue
            else:
                logger.error('logic error: tds_process_tokens result_type %d', result_type);

    def _fetchone(self, cursor):
        if self._active_cursor is not cursor:
            raise Error('This cursor is not active')
        """
        Helper method used by fetchone and fetchmany to fetch and handle
        """
        tds = self.tds_socket
        if tds.res_info is None:
            raise Error("Previous statement didn't produce any results")

        if self._state == DB_RES_NO_MORE_RESULTS:
            return None

        self._nextrow()

        if self._state != DB_RES_RESULTSET_ROWS:
            return None

        cols = tds.res_info.columns
        row = tuple(col.value for col in cols)
        if self.as_dict:
            row_dict = dict(enumerate(cols))
            row_dict.update(dict((col.column_name, col.value) for col in cols if col.column_name))
            row = row_dict
        return row

    def _nextset(self, cursor):
        if cursor is not self._active_cursor:
            raise Error('This cursor is not active')

        while self._state == DB_RES_RESULTSET_ROWS:
            self._nextrow()
        self._sqlok()
        return None if self._state == DB_RES_NO_MORE_RESULTS else True

    def _rowcount(self, cursor):
        if cursor is not self._active_cursor:
            return -1
        tds = self.tds_socket
        return tds.rows_affected

    def _get_proc_return_status(self, cursor):
        if cursor is not self._active_cursor:
            return None
        tds = self.tds_socket
        if not tds.has_status:
            tds_process_tokens(tds, TDS_RETURN_PROC)
        return tds.ret_status if tds.has_status else None

    def _description(self, cursor):
        if cursor is not self._active_cursor:
            return None
        res = self.tds_socket.res_info
        if res:
            return res.description
        else:
            return None

    def _native_description(self):
        if cursor is not self._active_cursor:
            return None
        res = self._conn.tds_socket.res_info
        if res:
            return res.native_descr
        else:
            return None

    def _close_cursor(self, cursor):
        if cursor is self._active_cursor:
            self._active_cursor = None
        cursor._conn = None

    def _try_activate_cursor(self, cursor):
        tds = self._get_connection()
        if cursor is self._active_cursor or self._active_cursor is None:
            self.cancel()
        else:
            if tds.state == TDS_PENDING:
                rc, result_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
                if rc != TDS_NO_MORE_RESULTS:
                    raise InterfaceError('Results are still pending on connection')
        self._active_cursor = cursor

    def _execute(self, cursor, operation, params):
        tds = self._get_connection()
        self._try_activate_cursor(cursor)
        tds_submit_query(tds, operation, params)
        self._state = DB_RES_INIT
        while True:
            tds_code, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

            #
            # The error flag may be set for any intervening DONEINPROC packet, in particular
            # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case. 
            #/
            if done_flags & TDS_DONE_ERROR:
                raise_db_exception(tds)
                assert False
                raise Exception('FAIL')
            if result_type == TDS_STATUS_RESULT:
                continue
            elif result_type == TDS_DONEINPROC_RESULT:
                if not done_flags & TDS_DONE_COUNT:
                    # skip results that don't event have rowcount
                    continue
                self._state = DB_RES_RESULTSET_EMPTY
                break
            elif result_type == TDS_ROWFMT_RESULT:
                self._state = DB_RES_RESULTSET_ROWS
                break
            elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                if done_flags & TDS_DONE_MORE_RESULTS:
                    if not done_flags & TDS_DONE_COUNT:
                        # skip results that don't event have rowcount
                        continue
                    self._state = DB_RES_NEXT_RESULT
                else:
                    self._state = DB_RES_NO_MORE_RESULTS
                break
            else:
                logger.error('logic error: tds_process_tokens result_type %d', result_type);

    def _callproc(self, cursor, procname, parameters):
        logger.debug('callproc begin')
        tds = self._get_connection()
        self._try_activate_cursor(cursor)
        tds_submit_rpc(tds, procname, parameters)
        tds.output_params = {}
        self._state = DB_RES_INIT
        while True:
            tds_code, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)
            #
            # The error flag may be set for any intervening DONEINPROC packet, in particular
            # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case. 
            #/
            if done_flags & TDS_DONE_ERROR:
                raise_db_exception(tds)
                assert False
                raise Exception('FAIL')
            if result_type == TDS_STATUS_RESULT:
                continue
            elif result_type == TDS_PARAM_RESULT:
                continue
            elif result_type == TDS_DONEINPROC_RESULT:
                self._state = DB_RES_RESULTSET_EMPTY
                continue
            elif result_type == TDS_ROWFMT_RESULT:
                self._state = DB_RES_RESULTSET_ROWS
                break
            elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                if done_flags & TDS_DONE_MORE_RESULTS:
                    if not done_flags & TDS_DONE_COUNT:
                        # skip results that don't event have rowcount
                        continue
                    self._state = DB_RES_NEXT_RESULT
                else:
                    self._state = DB_RES_NO_MORE_RESULTS
                break
            else:
                logger.error('logic error: tds_process_tokens result_type %d', result_type);
        logger.debug('callproc end')
        results = list(parameters)
        for key, param in tds.output_params.items():
            results[key] = param.value
        return results

##################
## Cursor class ##
##################
class _Cursor(object):
    """
    This class represents a database cursor, which is used to issue queries
    and fetch results from a database connection.
    """
    def __init__(self, conn):
        self._conn = conn
        self._batchsize = 1
        self.arraysize = 1

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self._conn is not None:
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
        return self._conn._callproc(self, procname, parameters)

    @property
    def return_value(self):
        return self.get_proc_return_status()

    @property
    def connection(self):
        return self._conn

    def get_proc_return_status(self):
        return self._conn._get_proc_return_status(self)

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        self._conn._close_cursor(self)

    def execute(self, operation, params=()):
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
        self._conn._execute(self, operation, params)

    def executemany(self, operation, params_seq):
        counts = []
        tds = self._conn.tds_socket
        for params in params_seq:
            self.execute(operation, params)
            if tds.rows_affected != -1:
                counts.append(tds.rows_affected)
        if counts:
            tds.rows_affected = sum(counts)

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
        return self._conn._nextset(self)

    @property
    def rowcount(self):
        return self._conn._rowcount(self)

    @property
    def description(self):
        return self._conn._description(self)

    @property
    def native_description(self):
        return self._conn._native_description(self)

    def fetchone(self):
        return self._conn._fetchone(self)

    def fetchmany(self, size=None):
        if size == None:
            size = self.arraysize

        rows = []
        for i in xrange(size):
            row = self.fetchone()
            if not row:
                break
            rows.append(row)
        return rows

    def fetchall(self):
        return list(row for row in self)

    def next(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
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
        login_timeout=60, as_dict=False,
        host='', appname=None, port=None, tds_version=TDS74,
        encryption_level=TDS_ENCRYPTION_OFF, autocommit=True,
        blocksize=4096):
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

    # support MS methods of connecting locally
    instance = ""
    if "\\" in server:
        server, instance = server.split("\\")

    if server in (".", "(local)"):
        server = "localhost"

    login = _TdsLogin()
    login.library = "Python TDS Library"
    login.encryption_level = encryption_level
    login.user_name = user or ''
    login.password = password or ''
    login.app_name = appname or 'pytds'
    login.port = port
    login.language = '' # use database default
    login.attach_db_file = ''
    login.tds_version = tds_version
    login.database = database
    login.emul_little_endian = False
    login.bulk_copy = False
    login.text_size = 0
    login.client_lcid = lcid.LANGID_ENGLISH_US

    # that will set:
    # ANSI_DEFAULTS to ON,
    # IMPLICIT_TRANSACTIONS to OFF,
    # TEXTSIZE to 0x7FFFFFFF (2GB) (TDS 7.2 and below), TEXTSIZE to infinite (introduced in TDS 7.3),
    # and ROWCOUNT to infinite
    login.option_flag2 = TDS_ODBC_ON

    login.connect_timeout = login_timeout
    login.query_timeout = timeout
    login.server_name = server
    login.instance_name = instance
    login.blocksize = blocksize
    return _Connection(login, as_dict, autocommit)

def Date(year, month, day):
    return date(year, month, day)

def DateFromTicks(ticks):
    return date.fromtimestamp(ticks)

def Time(hour, minute, second, microsecond=0):
    from datetime import time
    return time(hour, minute, second, microsecond)

def TimeFromTicks(ticks):
    import time
    return Time(*time.localtime(ticks)[3:6])

def Timestamp(year, month, day, hour, minute, second, microseconds=0):
    return datetime(year, month, day, hour, minute, second, microseconds)

def TimestampFromTicks(ticks):
    return datetime.fromtimestamp(ticks)
