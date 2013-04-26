"""DB-SIG compliant module for communicating with MS SQL servers"""

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = '1.5.0'

import logging
import six
from six.moves import xrange
from . import lcid
from datetime import date, datetime, time
from .tds import (
    Error, tds_quote_id,
    InterfaceError,
    TDS_PENDING, TDS74,
    TDS_ENCRYPTION_OFF, TDS_ODBC_ON, SimpleLoadBalancer,
    IS_TDS72_PLUS, TDS_IDLE,
    _TdsSocket,
    )

logger = logging.getLogger(__name__)

# comliant with DB SIG 2.0
apilevel = '2.0'

# module may be shared, but not connections
threadsafety = 1

# this module uses extended python format codes
paramstyle = 'pyformat'


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
                self._main_cursor._commit(cont=False)
            else:
                self._main_cursor._begin_tran(isolation_level=self._isolation_level)
            self._autocommit = value

    @property
    def isolation_level(self):
        return self._isolation_level

    def set_isolation_level(self, level):
        self._isolation_level = level

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
        self._conn = None
        self._conn = _TdsSocket(self._login)
        self._active_cursor = self._main_cursor = self.cursor()
        if not self._autocommit:
            self._main_cursor._begin_tran(isolation_level=self._isolation_level)

    def __init__(self, login, as_dict, autocommit=False):
        self._autocommit = autocommit
        self._login = login
        self._as_dict = as_dict
        self._isolation_level = 0
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
        self._main_cursor._commit(cont=True, isolation_level=self._isolation_level)

    def cursor(self):
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        self._assert_open()
        if self.mars_enabled:
            session = self._conn.create_session()
            return _MarsCursor(self, session)
        else:
            return _Cursor(self, self._conn.main_session)

    def rollback(self):
        """
        Roll back transaction which is currently in progress.
        """
        try:
            if self._autocommit:
                return

            if not self._conn or not self._conn.is_connected():
                return

            self._main_cursor._rollback(cont=True,
                                        isolation_level=self._isolation_level)
        except:
            logger.exception('unexpected error in rollback')

    def __del__(self):
        if self._conn is not None:
            self._conn.close()

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

    def _try_activate_cursor(self, cursor):
        if cursor is not self._active_cursor:
            session = self._active_cursor._session
            if session.state == TDS_PENDING:
                raise InterfaceError('Results are still pending on connection')
            self._active_cursor = cursor


##################
## Cursor class ##
##################
class _Cursor(six.Iterator):
    """
    This class represents a database cursor, which is used to issue queries
    and fetch results from a database connection.
    """
    def __init__(self, conn, session):
        self._conn = conn
        self.arraysize = 1
        self._session = session

    def _assert_open(self):
        if not self._conn:
            raise Error('Cursor is closed')
        self._conn._assert_open()
        self._session = self._conn._conn._main_session

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
        self._assert_open()
        self._conn._try_activate_cursor(self)
        return self._session.callproc(procname, parameters)

    @property
    def return_value(self):
        return self.get_proc_return_status()

    @property
    def connection(self):
        return self._conn

    @property
    def spid(self):
        return self._session._spid

    def get_proc_return_status(self):
        if self._session is None:
            return None
        if not self._session.has_status:
            self._session.find_return_status()
        return self._session.ret_status if self._session.has_status else None

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        if self._conn is not None:
            if self is self._conn._active_cursor:
                self._conn._active_cursor = self._conn._main_cursor
                self._session = None
            self._conn = None

    def execute(self, operation, params=()):
        # Execute the query
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.execute(operation, params)

    def _begin_tran(self, isolation_level):
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.begin_tran(isolation_level=isolation_level)

    def _commit(self, cont, isolation_level=0):
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.commit(cont=cont, isolation_level=isolation_level)

    def _rollback(self, cont, isolation_level=0):
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.rollback(cont=cont, isolation_level=isolation_level)

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
        return self._session.next_set()

    @property
    def rowcount(self):
        if self._session is None:
            return -1
        return self._session.rows_affected

    @property
    def description(self):
        if self._session is None:
            return None
        res = self._session.res_info
        if res:
            return res.description
        else:
            return None

    @property
    def native_description(self):
        if self._session is None:
            return None
        res = self._session.res_info
        if res:
            return res.native_descr
        else:
            return None

    def fetchone(self):
        return self._session.fetchone(self._conn.as_dict)

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


class _MarsCursor(_Cursor):
    def _assert_open(self):
        if not self._conn:
            raise Error('Cursor is closed')
        self._conn._assert_open()
        if not self._session.is_connected():
            self._session = self._conn._conn.create_session()

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        if self._conn is not None:
            self._session.close()
            self._conn = None

    def execute(self, operation, params=()):
        self._assert_open()
        self._session.execute(operation, params)

    def callproc(self, procname, parameters=()):
        """
        Call a stored procedure with the given name.

        :param procname: The name of the procedure to call
        :type procname: str
        :keyword parameters: The optional parameters for the procedure
        :type parameters: sequence
        """
        self._assert_open()
        return self._session.callproc(procname, parameters)

    def _begin_tran(self, isolation_level):
        self._assert_open()
        self._session.begin_tran(isolation_level=isolation_level)

    def _commit(self, cont, isolation_level=0):
        self._assert_open()
        self._session.commit(cont=cont, isolation_level=isolation_level)

    def _rollback(self, cont, isolation_level=0):
        self._assert_open()
        self._session.rollback(cont=cont, isolation_level=isolation_level)


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


def Time(hour, minute, second, microsecond=0, tzinfo=None):
    return time(hour, minute, second, microsecond, tzinfo)


def TimeFromTicks(ticks):
    import time
    return Time(*time.localtime(ticks)[3:6])


def Timestamp(year, month, day, hour, minute, second, microseconds=0, tzinfo=None):
    return datetime(year, month, day, hour, minute, second, microseconds, tzinfo)


def TimestampFromTicks(ticks):
    return datetime.fromtimestamp(ticks)
