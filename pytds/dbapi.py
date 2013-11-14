"""DB-SIG compliant module for communicating with MS SQL servers"""

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = '1.5.6'

import logging
import six
import errno
from . import lcid
from .tds import *
from .login import *
from .query import *

logger = logging.getLogger(__name__)

# comliant with DB SIG 2.0
apilevel = '2.0'

# module may be shared, but not connections
threadsafety = 1

# this module uses extended python format codes
paramstyle = 'pyformat'

DB_RES_INIT = 0
DB_RES_RESULTSET_EMPTY = 1
DB_RES_RESULTSET_ROWS = 2
DB_RES_NEXT_RESULT = 3
DB_RES_NO_MORE_RESULTS = 4
DB_RES_SUCCEED = 5


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
    def autocommit(self):
        return self._autocommit

    @autocommit.setter
    def autocommit(self, value):
        if self._autocommit != value:
            if value:
                if self._conn.tds72_transaction:
                    self._try_activate_cursor(None)
                    self._cancel(self._conn.main_session)
                    tds_submit_commit(self._conn.main_session, False)
                    self._sqlok(self._conn.main_session)
            else:
                self._cancel(self._conn.main_session)
                tds_submit_begin_tran(self._conn.main_session)
                self._sqlok(self._conn.main_session)
            self._autocommit = value

    def _assert_open(self):
        if not self._conn:
            raise Error('Connection closed')
        if not self._conn.is_connected():
            self._open()

    def _trancount(self):
        with self.cursor() as cur:
            cur.execute('select @@trancount')
            return cur.fetchone()[0]

    @property
    def chunk_handler(self):
        '''
        Returns current chunk handler
        Default is MemoryChunkedHandler()
        '''
        self._assert_open()
        return self._conn.chunk_handler

    @chunk_handler.setter
    def chunk_handler_set(self, value):
        self._assert_open()
        self._conn.chunk_handler = value

    @property
    def tds_version(self):
        '''
        Returns version of tds protocol that is being used by this connection
        '''
        self._assert_open()
        return self._conn.tds_version

    @property
    def product_version(self):
        '''
        Returns version of the server
        '''
        self._assert_open()
        return self._conn.product_version

    @property
    def mars_enabled(self):
        return self._conn.mars_enabled

    def _open(self):
        self._state = DB_RES_NO_MORE_RESULTS
        self._active_cursor = None
        from .tds import _TdsSocket
        self._conn = None
        self._dirty = False
        login = self._login
        if IS_TDS7_PLUS(login) and login.instance_name and not login.port:
            instances = tds7_get_instances(login.server_name)
            if login.instance_name not in instances:
                raise LoginError("Instance {0} not found on server {1}".format(login.instance_name, login.server_name))
            instdict = instances[login.instance_name]
            if 'tcp' not in instdict:
                raise LoginError("Instance {0} doen't have tcp connections enabled".format(login.instance_name))
            login.port = int(instdict['tcp'])
        if not login.port:
            login.port = 1433
        connect_timeout = login.connect_timeout
        login.query_timeout = login.connect_timeout if login.connect_timeout else login.query_timeout
        err = None
        for host in login.load_balancer.choose():
            try:
                sock = socket.create_connection(
                    (host, login.port),
                    connect_timeout or 90000)
                sock.settimeout(login.query_timeout)
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            except socket.error as e:
                err = LoginError("Cannot connect to server '{0}': {1}".format(host, e), e)
                continue
            try:
                self._conn = _TdsSocket(self._login, sock)
                break
            except Exception as e:
                sock.close()
                err = e
                #raise
                continue
        else:
            if not err:
                err = LoginError("Cannot connect to server, load balancer returned empty list")
            raise err
        self._active_cursor = self._main_cursor = self.cursor()
        if not self._autocommit:
            tds_submit_begin_tran(self._conn.main_session)
            self._sqlok(self._conn.main_session)

    def __init__(self, login, as_dict, autocommit=False):
        self._autocommit = autocommit
        self._login = login
        self._as_dict = as_dict
        self._open()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def commit(self):
        """
        Commit transaction which is currently in progress.
        """
        self._assert_open()
        if self._autocommit:
            return

        conn = self._conn
        if not conn.tds72_transaction:
            return

        self._try_activate_cursor(None)
        conn.main_session.messages = []
        self._cancel(conn.main_session)
        tds_submit_commit(conn.main_session, True)
        self._sqlok(conn.main_session)
        while self._nextset(conn.main_session):
            pass
        self._dirty = False

    def cursor(self):
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        self._assert_open()
        return _Cursor(self)

    def rollback(self):
        try:
            """
            Roll back transaction which is currently in progress.
            """
            if self._autocommit:
                return

            if not self._conn or not self._conn.is_connected():
                return

            if not self._conn.tds72_transaction:
                return

            session = self._conn.main_session
            session.messages = []
            self._cancel(session)
            self._active_cursor = None
            tds_submit_rollback(session, True)
            self._sqlok(session)
            while self._nextset(session):
                pass
            self._dirty = False
        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                return
        except ClosedConnectionError:
            pass
        except:
            logger.exception('unexpected error in rollback')

    def __del__(self):
        if self._conn is not None:
            self._conn.close()

    def _cancel(self, session):
        """
        cancel() -- cancel all pending results.

        This function cancels all pending results from the last SQL operation.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        #logger.debug("MSSQLConnection._cancel()")
        session.messages = []
        tds_send_cancel(session)
        tds_process_cancel(session)

    def close(self):
        """
        close() -- close connection to an MS SQL Server.

        This function tries to close the connection and free all memory used.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        #logger.debug("MSSQLConnection.close()")
        if self._conn:
            self._conn.close()
            self._conn = None

    def select_db(self, dbname):
        """
        select_db(dbname) -- Select the current database.

        This function selects the given database. An exception is raised on
        failure.
        """
        #logger.debug("MSSQLConnection.select_db()")
        self._assert_open()
        cur = self.cursor()
        try:
            cur.execute('use {0}'.format(tds_quote_id(self._conn, dbname)))
        finally:
            cur.close()

    _nextrow_mask = TDS_STOPAT_ROWFMT | TDS_RETURN_DONE | TDS_RETURN_ROW | TDS_RETURN_COMPUTE

    def _nextrow(self, session):
        #logger.debug("_nextrow()")
        resinfo = session.res_info
        if not resinfo or self._state != DB_RES_RESULTSET_ROWS:
            # no result set or result set empty (no rows)
            #logger.debug("leaving _nextrow() returning NO_MORE_ROWS")
            return

        # Get the row from the TDS stream.
        try:
            rc, res_type, done_flags = tds_process_tokens(session, self._nextrow_mask)
        except:
            session.close()
            raise
        if done_flags & TDS_DONE_ERROR:
            raise_db_exception(session)
            assert False
            raise Exception('FAIL')
        if rc == TDS_SUCCESS:
            if res_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                # Add the row to the row buffer, whose capacity is always at least 1
                resinfo = session.current_results
                #_, res_type, _ = tds_process_tokens(session, TDS_TOKEN_TRAILING)
            else:
                self._state = DB_RES_NEXT_RESULT
        elif rc == TDS_NO_MORE_RESULTS:
            self._state = DB_RES_NEXT_RESULT
        else:
            raise Exception("unexpected result from tds_process_tokens")

    def _sqlok(self, session):
        #logger.debug("dbsqlok()")
        #CHECK_CONN(FAIL);

        #
        # If we hit an end token -- e.g. if the command
        # submitted returned no data (like an insert) -- then
        # we process the end token to extract the status code.
        #
        #logger.debug("dbsqlok() not done, calling tds_process_tokens()")
        while True:
            tds_code, result_type, done_flags = tds_process_tokens(session, TDS_TOKEN_RESULTS)

            #
            # The error flag may be set for any intervening DONEINPROC packet, in particular
            # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case.
            #/
            if done_flags & TDS_DONE_ERROR:
                raise_db_exception(session)
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
                raise Exception('Invalid result type: ' + str(result_type))


    def _fetchone(self, cursor):
        """
        Helper method used by fetchone and fetchmany to fetch and handle
        """
        session = cursor._session
        if session is None:
            raise Error('This cursor is not active')
        if session.res_info is None:
            raise Error("Previous statement didn't produce any results")

        if self._state == DB_RES_NO_MORE_RESULTS:
            return None

        self._nextrow(session)

        if self._state != DB_RES_RESULTSET_ROWS:
            return None

        cols = session.res_info.columns
        row = tuple(col.value for col in cols)
        if self.as_dict:
            row = dict((col.column_name, col.value) for col in cols if col.column_name)
        return row

    def _nextset(self, session):
        if session is None:
            raise Error('This cursor is not active')

        while self._state == DB_RES_RESULTSET_ROWS:
            self._nextrow(session)
        self._sqlok(session)
        return None if self._state == DB_RES_NO_MORE_RESULTS else True

    def _rowcount(self, cursor):
        session = cursor._session
        if session is None:
            return -1
        return session.rows_affected

    def _get_proc_return_status(self, cursor):
        session = cursor._session
        if session is None:
            return None
        if not session.has_status:
            tds_process_tokens(session, TDS_RETURN_PROC)
        return session.ret_status if session.has_status else None

    def _description(self, cursor):
        session = cursor._session
        if session is None:
            return None
        res = session.res_info
        if res:
            return res.description
        else:
            return None

    def _native_description(self, cursor):
        session = cursor._session
        if session is None:
            return None
        res = session.res_info
        if res:
            return res.native_descr
        else:
            return None

    def _close_cursor(self, cursor):
        if self._conn is not None and cursor._session is not None:
            if self._conn.mars_enabled:
                try:
                    cursor._session.close()
                except socket.error as e:
                    if e.errno != errno.ECONNRESET:
                        raise
            else:
                if cursor is self._active_cursor:
                    self._active_cursor = None
                    self._session = None
        cursor._conn = None

    def _try_activate_cursor(self, cursor):
        conn = self._conn
        if cursor is not None and not cursor._session.is_connected():
            cursor._open()
        if not conn.mars_enabled:
            if not (cursor is self._active_cursor or self._active_cursor is None):
                session = conn.main_session
                if session.state == TDS_PENDING:
                    rc, result_type, _ = tds_process_tokens(session, TDS_TOKEN_TRAILING)
                    if rc != TDS_NO_MORE_RESULTS:
                        raise InterfaceError('Results are still pending on connection')
                if cursor is not None:
                    cursor._session = session
            self._active_cursor = cursor

    def _execute(self, cursor, operation, params):
        self._assert_open()
        self._try_activate_cursor(cursor)
        session = cursor._session
        session.messages = []
        self._cancel(session)
        tds_submit_query(session, operation, params)
        self._state = DB_RES_INIT
        while True:
            tds_code, result_type, done_flags = tds_process_tokens(session, TDS_TOKEN_RESULTS)

            #
            # The error flag may be set for any intervening DONEINPROC packet, in particular
            # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case.
            #/
            if done_flags & TDS_DONE_ERROR:
                raise_db_exception(session)
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
                logger.error('logic error: tds_process_tokens result_type %d', result_type)

    def _exec_with_retry(self, fun):
        self._assert_open()
        in_tran = self._conn.tds72_transaction
        if in_tran and self._dirty:
            self._dirty = True
            return fun()
        else:
            # first attemp
            try:
                self._dirty = True
                return fun()
            except socket.error as e:
                if e.errno != errno.ECONNRESET:
                    raise
            # try again if connection was reset
            self._assert_open()
            return fun()

    def _callproc(self, cursor, procname, parameters):
        #logger.debug('callproc begin')
        self._assert_open()
        self._try_activate_cursor(cursor)
        session = cursor._session
        session.messages = []
        self._cancel(session)
        tds_submit_rpc(session, procname, parameters)
        session.output_params = {}
        self._state = DB_RES_INIT
        while True:
            tds_code, result_type, done_flags = tds_process_tokens(session, TDS_TOKEN_RESULTS)
            #
            # The error flag may be set for any intervening DONEINPROC packet, in particular
            # by a RAISERROR statement.  Microsoft db-lib returns FAIL in that case.
            #/
            if done_flags & TDS_DONE_ERROR:
                raise_db_exception(session)
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
                logger.error('logic error: tds_process_tokens result_type %d', result_type)
        #logger.debug('callproc end')
        results = list(parameters)
        for key, param in session.output_params.items():
            results[key] = param.value
        return results


##################
## Cursor class ##
##################
class _Cursor(six.Iterator):
    """
    This class represents a database cursor, which is used to issue queries
    and fetch results from a database connection.
    """
    def __init__(self, conn):
        self._conn = conn
        self._batchsize = 1
        self.arraysize = 1
        self._open()

    def _open(self):
        if self._conn._conn.mars_enabled:
            in_tran = self._conn._conn.tds72_transaction
            if in_tran and self._conn._dirty:
                self._session = self._conn._conn.create_session()
            else:
                try:
                    self._session = self._conn._conn.create_session()
                    return
                except socket.error as e:
                    if e.errno != errno.ECONNRESET:
                        raise
                except ClosedConnectionError:
                    pass
                self._conn._assert_open()
                self._session = self._conn._conn.create_session()
        else:
            self._session = self._conn._conn.main_session

    def __del__(self):
        self.close()

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
        return self._conn._exec_with_retry(lambda: self._conn._callproc(self, procname, parameters))

    @property
    def return_value(self):
        return self.get_proc_return_status()

    @property
    def connection(self):
        return self._conn

    @property
    def spid(self):
        # not thread safe for connection
        dirty = self._conn._dirty
        spid = self.execute_scalar('select @@SPID')
        self._conn._dirty = dirty
        return spid

    def get_proc_return_status(self):
        return self._conn._get_proc_return_status(self)

    def cancel(self):
        self._conn._cancel(self._session)

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        if self._conn is not None:
            self._conn._close_cursor(self)

    def _execute(self, operation, params):
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
            #logger.debug('converted query: {0}'.format(operation))
            #logger.debug('params: {0}'.format(params))
        self._conn._execute(self, operation, params)

    def execute(self, operation, params=()):
        self._conn._exec_with_retry(lambda: self._execute(operation, params))

    def executemany(self, operation, params_seq):
        counts = []
        for params in params_seq:
            self.execute(operation, params)
            if self._session.rows_affected != -1:
                counts.append(self._session.rows_affected)
        if counts:
            self._session.rows_affected = sum(counts)

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
        return self._conn._nextset(self._session)

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
        if size is None:
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

    def __next__(self):
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
            encryption_level=TDS_ENCRYPTION_OFF, autocommit=False,
            blocksize=4096, use_mars=False, auth=None, readonly=False,
            load_balancer=None, use_tz=None):
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
    login.language = ''  # use database default
    login.attach_db_file = ''
    login.tds_version = tds_version
    login.database = database
    login.emul_little_endian = False
    login.bulk_copy = False
    login.text_size = 0
    login.client_lcid = lcid.LANGID_ENGLISH_US
    login.use_mars = use_mars

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
    login.auth = auth
    login.readonly = readonly
    login.load_balancer = load_balancer or SimpleLoadBalancer([server])
    login.use_tz = use_tz
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


def Timestamp(year, month, day, hour, minute, second, microseconds=0, tzinfo=None):
    return datetime(year, month, day, hour, minute, second, microseconds, tzinfo)


def TimestampFromTicks(ticks):
    return datetime.fromtimestamp(ticks)
