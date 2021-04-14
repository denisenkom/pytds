"""DB-SIG compliant module for communicating with MS SQL servers"""
from collections import deque
import datetime
import errno
import keyword
import os
import re
import six
import socket
import uuid
import warnings
import weakref
import logging

from six.moves import xrange

from pytds.tds_types import NVarCharType
from . import lcid
import pytds.tz
from .tds import (
    _TdsSocket, tds7_get_instances,
    _create_exception_by_message,
    output, default
)
from . import tds_base
from .tds_base import (
    Error, LoginError, DatabaseError, ProgrammingError,
    IntegrityError, DataError, InternalError,
    InterfaceError, TimeoutError, OperationalError,
    NotSupportedError, Warning, ClosedConnectionError,
    Column,
    PreLoginEnc)

from .tds_types import (
    TableValuedParam, Binary
)

from .tds_base import (
    ROWID, DECIMAL, STRING, BINARY, NUMBER, DATETIME, INTEGER, REAL, XML
)

from . import tls
import pkg_resources

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = pkg_resources.get_distribution('python-tds').version

logger = logging.getLogger(__name__)


def _ver_to_int(ver):
    res = ver.split('.')
    if len(res) < 2:
        logger.warning('Invalid version {}, it should have 2 parts at least separated by "."'.format(ver))
        return 0
    maj, minor, _ = ver.split('.')
    return (int(maj) << 24) + (int(minor) << 16)


intversion = _ver_to_int(__version__)

#: Compliant with DB SIG 2.0
apilevel = '2.0'

#: Module may be shared, but not connections
threadsafety = 1

#: This module uses extended python format codes
paramstyle = 'pyformat'


class _TdsLogin:
    pass


def tuple_row_strategy(column_names):
    """ Tuple row strategy, rows returned as tuples, default
    """
    return tuple


def list_row_strategy(column_names):
    """  List row strategy, rows returned as lists
    """
    return list


def dict_row_strategy(column_names):
    """ Dict row strategy, rows returned as dictionaries
    """
    # replace empty column names with indices
    column_names = [(name or idx) for idx, name in enumerate(column_names)]

    def row_factory(row):
        return dict(zip(column_names, row))

    return row_factory


def is_valid_identifier(name):
    return name and re.match("^[_A-Za-z][_a-zA-Z0-9]*$", name) and not keyword.iskeyword(name)


def namedtuple_row_strategy(column_names):
    """ Namedtuple row strategy, rows returned as named tuples

    Column names that are not valid Python identifiers will be replaced
    with col<number>_
    """
    import collections
    # replace empty column names with placeholders
    column_names = [name if is_valid_identifier(name) else 'col%s_' % idx for idx, name in enumerate(column_names)]
    row_class = collections.namedtuple('Row', column_names)

    def row_factory(row):
        return row_class(*row)

    return row_factory


def recordtype_row_strategy(column_names):
    """ Recordtype row strategy, rows returned as recordtypes

    Column names that are not valid Python identifiers will be replaced
    with col<number>_
    """
    try:
        from namedlist import namedlist as recordtype  # optional dependency
    except ImportError:
        from recordtype import recordtype  # optional dependency
    # replace empty column names with placeholders
    column_names = [name if is_valid_identifier(name) else 'col%s_' % idx for idx, name in enumerate(column_names)]
    recordtype_row_class = recordtype('Row', column_names)

    # custom extension class that supports indexing
    class Row(recordtype_row_class):
        def __getitem__(self, index):
            if isinstance(index, slice):
                return tuple(getattr(self, x) for x in self.__slots__[index])
            return getattr(self, self.__slots__[index])

        def __setitem__(self, index, value):
            setattr(self, self.__slots__[index], value)

    def row_factory(row):
        return Row(*row)

    return row_factory


class _ConnectionPool(object):
    def __init__(self, max_pool_size=100, min_pool_size=0):
        self._max_pool_size = max_pool_size
        self._pool = {}

    def add(self, key, conn):
        l = self._pool.setdefault(key, []).append(conn)

    def take(self, key):
        l = self._pool.get(key, [])
        if len(l) > 0:
            return l.pop()
        else:
            return None


_connection_pool = _ConnectionPool()


class Connection(object):
    """Connection object, this object should be created by calling :func:`connect`"""

    def __init__(self):
        self._closed = False
        self._conn = None
        self._isolation_level = 0
        self._autocommit = True
        self._row_strategy = tuple_row_strategy
        self._login = None
        self._use_tz = None
        self._tzinfo_factory = None
        self._key = None
        self._pooling = False

    @property
    def as_dict(self):
        """
        Instructs all cursors this connection creates to return results
        as a dictionary rather than a tuple.
        """
        return self._row_strategy == dict_row_strategy

    @as_dict.setter
    def as_dict(self, value):
        if value:
            self._row_strategy = dict_row_strategy
        else:
            self._row_strategy = tuple_row_strategy

    @property
    def autocommit_state(self):
        """
        An alias for `autocommit`, provided for compatibility with pymssql
        """
        return self._autocommit

    def set_autocommit(self, value):
        """ An alias for `autocommit`, provided for compatibility with ADO dbapi
        """
        self.autocommit = value

    @property
    def autocommit(self):
        """
        The current state of autocommit on the connection.
        """
        return self._autocommit

    @autocommit.setter
    def autocommit(self, value):
        if self._autocommit != value:
            if value:
                if self._conn.tds72_transaction:
                    self._main_cursor._rollback(cont=False)
            else:
                self._main_cursor._begin_tran(isolation_level=self._isolation_level)
            self._autocommit = value

    @property
    def isolation_level(self):
        """Isolation level for transactions,
        for possible values see :ref:`isolation-level-constants`

        .. seealso:: `SET TRANSACTION ISOLATION LEVEL`__ in MSSQL documentation

            .. __: http://msdn.microsoft.com/en-us/library/ms173763.aspx
        """
        return self._isolation_level

    @isolation_level.setter
    def isolation_level(self, level):
        self._isolation_level = level

    def _assert_open(self):
        if self._closed:
            raise Error('Connection closed')
        if not self._conn or not self._conn.is_connected():
            self._open()

    def _trancount(self):
        with self.cursor() as cur:
            cur.execute('select @@trancount')
            return cur.fetchone()[0]

    @property
    def tds_version(self):
        """
        Version of tds protocol that is being used by this connection
        """
        self._assert_open()
        return self._conn.tds_version

    @property
    def product_version(self):
        """
        Version of the MSSQL server
        """
        self._assert_open()
        return self._conn.product_version

    @property
    def mars_enabled(self):
        """ Whether MARS is enabled or not on connection
        """
        return self._conn.mars_enabled

    def _connect(self, host, port, instance, timeout, sock=None):
        login = self._login

        try:
            login.server_name = host
            login.instance_name = instance
            port = _resolve_instance_port(
                host,
                port,
                instance,
                timeout=timeout)
            if not sock:
                logger.info('Opening socket to %s:%d', host, port)
                sock = socket.create_connection((host, port), timeout)
        except Exception as e:
            raise LoginError("Cannot connect to server '{0}': {1}".format(host, e), e)

        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        # default keep alive should be 30 seconds according to spec:
        # https://msdn.microsoft.com/en-us/library/dd341108.aspx
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 30)

        sock.settimeout(timeout)
        conn = _TdsSocket(self._use_tz)
        self._conn = conn
        try:
            route = conn.login(login, sock, self._tzinfo_factory)
            if route is not None:
                # rerouted to different server
                sock.close()
                self._connect(host=route['server'],
                              port=route['port'],
                              instance=instance,
                              timeout=timeout)
                return

            if conn.mars_enabled:
                cursor = _MarsCursor(
                    self,
                    conn.create_session(self._tzinfo_factory),
                    self._tzinfo_factory)
            else:
                cursor = Cursor(
                    self,
                    conn.main_session,
                    self._tzinfo_factory)

            self._active_cursor = self._main_cursor = cursor
            if not self._autocommit:
                cursor._session.begin_tran(isolation_level=self._isolation_level)
            sock.settimeout(login.query_timeout)
        except:
            sock.close()
            raise

    def _try_open(self, timeout, sock=None):
        if self._pooling:
            res = _connection_pool.take(self._key)
            if res is not None:
                self._conn, sess = res
                if self._conn.mars_enabled:
                    cursor = _MarsCursor(
                        self,
                        sess,
                        self._tzinfo_factory)
                else:
                    cursor = Cursor(
                        self,
                        sess,
                        self._tzinfo_factory)
                self._active_cursor = self._main_cursor = cursor
                cursor.callproc('sp_reset_connection')
                return

        login = self._login
        host, port, instance = login.servers[0]
        self._connect(host=host, port=port, instance=instance, timeout=timeout, sock=sock)

    def _open(self, sock=None):
        import time
        self._conn = None
        self._dirty = False
        login = self._login
        connect_timeout = login.connect_timeout

        # using retry algorithm specified in
        # http://msdn.microsoft.com/en-us/library/ms175484.aspx
        retry_time = 0.08 * connect_timeout
        retry_delay = 0.2
        last_error = None
        end_time = time.time() + connect_timeout
        while True:
            for _ in xrange(len(login.servers)):
                try:
                    self._try_open(timeout=retry_time, sock=sock)
                    return
                except OperationalError as e:
                    last_error = e
                    # if there are more than one message this means
                    # that the login was successful, like in the
                    # case when database is not accessible
                    # mssql returns 2 messages:
                    # 1) Cannot open database "<dbname>" requested by the login. The login failed.
                    # 2) Login failed for user '<username>'
                    # in this case we want to retry
                    if self._conn is not None and len(self._conn.main_session.messages) <= 1:
                        # for the following error messages we don't retry
                        # because if the password is incorrect and we
                        # retry multiple times this can cause account
                        # to be locked
                        if e.msg_no in (
                                18456,  # login failed
                                18486,  # account is locked
                                18487,  # password expired
                                18488,  # password should be changed
                                18452,  # login from untrusted domain
                        ):
                            raise

                if time.time() > end_time:
                    raise last_error
                login.servers.rotate(-1)

            time.sleep(retry_delay)
            retry_time += 0.08 * connect_timeout
            retry_delay = min(1, retry_delay * 2)

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
        if not self._conn.tds72_transaction:
            return
        self._main_cursor._commit(cont=True, isolation_level=self._isolation_level)

    def cursor(self):
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        self._assert_open()
        if self.mars_enabled:
            in_tran = self._conn.tds72_transaction
            if in_tran and self._dirty:
                try:
                    return _MarsCursor(self,
                                       self._conn.create_session(self._tzinfo_factory),
                                       self._tzinfo_factory)
                except (socket.error, OSError) as e:
                    self._conn.close()
                    raise
            else:
                try:
                    return _MarsCursor(self,
                                       self._conn.create_session(self._tzinfo_factory),
                                       self._tzinfo_factory)
                except (socket.error, OSError) as e:
                    if e.errno not in (errno.EPIPE, errno.ECONNRESET):
                        raise
                    self._conn.close()
                except ClosedConnectionError:
                    pass
                self._assert_open()
                return _MarsCursor(self,
                                   self._conn.create_session(self._tzinfo_factory),
                                   self._tzinfo_factory)
        else:
            return Cursor(self,
                          self._conn.main_session,
                          self._tzinfo_factory)

    def rollback(self):
        """
        Roll back transaction which is currently in progress.
        """
        try:
            if self._autocommit:
                return

            if not self._conn or not self._conn.is_connected():
                return

            if not self._conn.tds72_transaction:
                return

            self._main_cursor._rollback(cont=True,
                                        isolation_level=self._isolation_level)
        except socket.error as e:
            if e.errno in (errno.ENETRESET, errno.ECONNRESET, errno.EPIPE):
                return
            self._conn.close()
            raise
        except ClosedConnectionError:
            pass

    def close(self):
        """ Close connection to an MS SQL Server.

        This function tries to close the connection and free all memory used.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        if self._conn:
            if self._pooling:
                _connection_pool.add(self._key, (self._conn, self._main_cursor._session))
            else:
                self._conn.close()
            self._active_cursor = None
            self._main_cursor = None
            self._conn = None
        self._closed = True

    def _try_activate_cursor(self, cursor):
        if cursor is not self._active_cursor:
            session = self._active_cursor._session
            if session.in_cancel:
                session.process_cancel()

            if session.state == tds_base.TDS_PENDING:
                raise InterfaceError('Results are still pending on connection')
            self._active_cursor = cursor


class Cursor(six.Iterator):
    """
    This class represents a database cursor, which is used to issue queries
    and fetch results from a database connection.
    """
    def __init__(self, conn, session, tzinfo_factory):
        self._conn = weakref.ref(conn)
        self.arraysize = 1
        self._session = session
        self._tzinfo_factory = tzinfo_factory

    def _assert_open(self):
        conn = self._conn
        if conn is not None:
            conn = conn()
        if not conn:
            raise InterfaceError('Cursor is closed')
        conn._assert_open()
        self._session = conn._conn._main_session
        return conn

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

    def _setup_row_factory(self):
        self._row_factory = None
        conn = self._conn()
        if self._session.res_info:
            column_names = [col[0] for col in self._session.res_info.description]
            self._row_factory = conn._row_strategy(column_names)

    def _callproc(self, procname, parameters):
        self._ensure_transaction()
        results = list(parameters)
        parameters = self._session._convert_params(parameters)
        self._exec_with_retry(lambda: self._session.submit_rpc(procname, parameters, 0))
        self._session.process_rpc()
        for key, param in self._session.output_params.items():
            results[key] = param.value
        self._setup_row_factory()
        return results

    def get_proc_outputs(self):
        """
        If stored procedure has result sets and OUTPUT parameters use this method
        after you processed all result sets to get values of OUTPUT parameters.
        :return: A list of output parameter values.
        """

        self._session.complete_rpc()
        results = [None] * len(self._session.output_params.items())
        for key, param in self._session.output_params.items():
            results[key] = param.value
        return results

    def callproc(self, procname, parameters=()):
        """
        Call a stored procedure with the given name.

        :param procname: The name of the procedure to call
        :type procname: str
        :keyword parameters: The optional parameters for the procedure
        :type parameters: sequence

        Note: If stored procedure has OUTPUT parameters and result sets this
        method will not return values for OUTPUT parameters, you should
        call get_proc_outputs to get values for OUTPUT parameters.
        """
        conn = self._assert_open()
        conn._try_activate_cursor(self)
        return self._callproc(procname, parameters)

    @property
    def return_value(self):
        """  Alias to :func:`get_proc_return_status`
        """
        return self.get_proc_return_status()

    @property
    def connection(self):
        """ Provides link back to :class:`Connection` of this cursor
        """
        return self._conn()

    @property
    def spid(self):
        """ MSSQL Server's SPID (session id)
        """
        return self._session._spid

    def _get_tzinfo_factory(self):
        return self._tzinfo_factory

    def _set_tzinfo_factory(self, tzinfo_factory):
        self._tzinfo_factory = self._session.tzinfo_factory = tzinfo_factory

    tzinfo_factory = property(_get_tzinfo_factory, _set_tzinfo_factory)

    def get_proc_return_status(self):
        """ Last stored proc result
        """
        if self._session is None:
            return None
        if not self._session.has_status:
            self._session.find_return_status()
        return self._session.ret_status if self._session.has_status else None

    def cancel(self):
        """ Cancel current statement
        """
        conn = self._assert_open()
        conn._try_activate_cursor(self)
        self._session.cancel_if_pending()

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        conn = self._conn
        if conn is not None:
            conn = conn()
        if conn is not None:
            if self is conn._active_cursor:
                conn._active_cursor = conn._main_cursor
                self._session = None
            self._conn = None

    def _exec_with_retry(self, fun):
        conn = self._assert_open()
        in_tran = conn._conn.tds72_transaction
        if in_tran and conn._dirty:
            conn._dirty = True
            try:
                return fun()
            except socket.error as e:
                if e.errno not in (errno.ECONNRESET, errno.EPIPE):
                    raise
                conn._conn.close()
        else:
            conn._dirty = True
            try:
                return fun()
            except socket.error as e:
                if e.errno not in (errno.ECONNRESET, errno.EPIPE):
                    raise
                conn._conn.close()
            except ClosedConnectionError:
                pass
            # in case of connection reset try again
            conn = self._assert_open()
            return fun()

    def _ensure_transaction(self):
        conn = self._conn()
        if not conn._autocommit and not conn._conn.tds72_transaction:
            conn._main_cursor._begin_tran(isolation_level=conn._isolation_level)

    def _execute(self, operation, params):
        self._ensure_transaction()
        operation = six.text_type(operation)
        if params:
            named_params = {}
            if isinstance(params, (list, tuple)):
                names = []
                pid = 1
                for val in params:
                    if val is None:
                        names.append('NULL')
                    else:
                        name = '@P{0}'.format(pid)
                        names.append(name)
                        named_params[name] = val
                        pid += 1
                if len(names) == 1:
                    operation = operation % names[0]
                else:
                    operation = operation % tuple(names)
            elif isinstance(params, dict):
                # prepend names with @
                rename = {}
                for name, value in params.items():
                    if value is None:
                        rename[name] = 'NULL'
                    else:
                        mssql_name = '@{0}'.format(name)
                        rename[name] = mssql_name
                        named_params[mssql_name] = value
                operation = operation % rename
            if named_params:
                named_params = self._session._convert_params(named_params)
                param_definition = u','.join(
                    u'{0} {1}'.format(p.column_name, p.type.get_declaration())
                    for p in named_params)
                self._exec_with_retry(lambda: self._session.submit_rpc(
                    tds_base.SP_EXECUTESQL,
                    [self._session.make_param('', operation), self._session.make_param('', param_definition)] + named_params,
                    0))
            else:
                self._exec_with_retry(lambda: self._session.submit_plain_query(operation))
        else:
            self._exec_with_retry(lambda: self._session.submit_plain_query(operation))
        self._session.find_result_or_done()
        self._setup_row_factory()

    def execute(self, operation, params=()):
        """ Execute the query

        :param operation: SQL statement
        :type operation: str
        """
        conn = self._assert_open()
        conn._try_activate_cursor(self)
        self._execute(operation, params)
        # for compatibility with pyodbc
        return self

    def _begin_tran(self, isolation_level):
        conn = self._assert_open()
        conn._try_activate_cursor(self)
        self._session.begin_tran(isolation_level=isolation_level)

    def _commit(self, cont, isolation_level=0):
        conn = self._assert_open()
        conn._try_activate_cursor(self)
        self._session.commit(cont=cont, isolation_level=isolation_level)
        conn._dirty = False

    def _rollback(self, cont, isolation_level=0):
        conn = self._assert_open()
        conn._try_activate_cursor(self)
        self._session.rollback(cont=cont, isolation_level=isolation_level)
        conn._dirty = False

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
        This method sends a query to the MS SQL Server to which this object
        instance is connected, then returns first column of first row from
        result. An exception is raised on failure. If there are pending

        results or rows prior to executing this command, they are silently
        discarded.

        This method accepts Python formatting. Please see execute_query()
        for details.

        This method is useful if you want just a single value, as in:

            ``conn.execute_scalar('SELECT COUNT(*) FROM employees')``

        This method works in the same way as ``iter(conn).next()[0]``.
        Remaining rows, if any, can still be iterated after calling this
        method.
        """
        self.execute(query_string, params)
        row = self.fetchone()
        if not row:
            return None
        return row[0]

    def nextset(self):
        """ Move to next recordset in batch statement, all rows of current recordset are
        discarded if present.

        :returns: true if successful or ``None`` when there are no more recordsets
        """
        res = self._session.next_set()
        self._setup_row_factory()
        return res

    @property
    def rowcount(self):
        """ Number of rows affected by previous statement

        :returns: -1 if this information was not supplied by MSSQL server
        """
        if self._session is None:
            return -1
        return self._session.rows_affected

    @property
    def description(self):
        """ Cursor description, see http://legacy.python.org/dev/peps/pep-0249/#description
        """
        if self._session is None:
            return None
        res = self._session.res_info
        if res:
            return res.description
        else:
            return None

    def set_stream(self, column_idx, stream):
        if len(self._session.res_info.columns) <= column_idx or column_idx < 0:
            raise ValueError('Invalid value for column_idx')
        self._session.res_info.columns[column_idx].serializer.set_chunk_handler(pytds.tds_types._StreamChunkedHandler(stream))

    @property
    def messages(self):
        """ Messages generated by server, see http://legacy.python.org/dev/peps/pep-0249/#cursor-messages
        """
        if self._session:
            result = []
            for msg in self._session.messages:
                ex = _create_exception_by_message(msg)
                result.append((type(ex), ex))
            return result
        else:
            return None

    @property
    def native_description(self):
        """ todo document
        """
        if self._session is None:
            return None
        res = self._session.res_info
        if res:
            return res.native_descr
        else:
            return None

    def fetchone(self):
        """ Fetches next row, or ``None`` if there are no more rows
        """
        row = self._session.fetchone()
        if row:
            return self._row_factory(row)

    def fetchmany(self, size=None):
        """ Fetches next multiple rows

        :param size: Maximum number of rows to return, default value is cursor.arraysize
        :returns: List of rows
        """
        if size is None:
            size = self.arraysize

        rows = []
        for _ in xrange(size):
            row = self.fetchone()
            if not row:
                break
            rows.append(row)
        return rows

    def fetchall(self):
        """ Fetches all remaining rows
        """
        return list(row for row in self)

    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    @staticmethod
    def setinputsizes(sizes=None):
        """
        This method does nothing, as permitted by DB-API specification.
        """
        pass

    @staticmethod
    def setoutputsize(size=None, column=0):
        """
        This method does nothing, as permitted by DB-API specification.
        """
        pass

    def copy_to(self, file=None, table_or_view=None, sep='\t', columns=None,
                check_constraints=False, fire_triggers=False, keep_nulls=False,
                kb_per_batch=None, rows_per_batch=None, order=None, tablock=False,
                schema=None, null_string=None, data=None):
        """ *Experimental*. Efficiently load data to database from file using ``BULK INSERT`` operation

        :param file: Source file-like object, should be in csv format. Specify
          either this or data, not both.
        :param table_or_view: Destination table or view in the database
        :type table_or_view: str

        Optional parameters:

        :keyword sep: Separator used in csv file
        :type sep: str
        :keyword columns: List of Column objects or column names in target
          table to insert to. SQL Server will do some conversions, so these
          may not have to match the actual table definition exactly.
          If not provided will insert into all columns assuming nvarchar(4000)
          NULL for all columns.
          If only the column name is provided, the type is assumed to be
          nvarchar(4000) NULL.
          If rows are given with file, you cannot specify non-string data
          types.
          If rows are given with data, the values must be a type supported by
          the serializer for the column in tds_types.
        :type columns: list
        :keyword check_constraints: Check table constraints for incoming data
        :type check_constraints: bool
        :keyword fire_triggers: Enable or disable triggers for table
        :type fire_triggers: bool
        :keyword keep_nulls: If enabled null values inserted as-is, instead of
          inserting default value for column
        :type keep_nulls: bool
        :keyword kb_per_batch: Kilobytes per batch can be used to optimize performance, see MSSQL
          server documentation for details
        :type kb_per_batch: int
        :keyword rows_per_batch: Rows per batch can be used to optimize performance, see MSSQL
          server documentation for details
        :type rows_per_batch: int
        :keyword order: The ordering of the data in source table. List of columns with ASC or DESC suffix.
          E.g. ``['order_id ASC', 'name DESC']``
          Can be used to optimize performance, see MSSQL server documentation for details
        :type order: list
        :keyword tablock: Enable or disable table lock for the duration of bulk load
        :keyword schema: Name of schema for table or view, if not specified default schema will be used
        :keyword null_string: String that should be interpreted as a NULL when
          reading the CSV file. Has no meaning if using data instead of file.
        :keyword data: The data to insert as an iterable of rows, which are
          iterables of values. Specify either this or file, not both.
        """
        conn = self._conn()
        rows = None
        if data is None:
            import csv
            reader = csv.reader(file, delimiter=sep)

            if null_string is not None:
                def _convert_null_strings(csv_reader):
                    for row in csv_reader:
                        yield [r if r != null_string else None for r in row]

                reader = _convert_null_strings(reader)

            rows = reader
        else:
            rows = data

        obj_name = tds_base.tds_quote_id(table_or_view)
        if schema:
            obj_name = '{0}.{1}'.format(tds_base.tds_quote_id(schema), obj_name)
        if columns:
            metadata = []
            for column in columns:
                if isinstance(column, Column):
                    metadata.append(column)
                else:
                    metadata.append(Column(name=column, type=NVarCharType(size=4000), flags=Column.fNullable))
        else:
            self.execute('select top 1 * from {} where 1<>1'.format(obj_name))
            metadata = [Column(name=col[0], type=NVarCharType(size=4000), flags=Column.fNullable if col[6] else 0)
                        for col in self.description]
        col_defs = ','.join('{0} {1}'.format(tds_base.tds_quote_id(col.column_name), col.type.get_declaration())
                            for col in metadata)
        with_opts = []
        if check_constraints:
            with_opts.append('CHECK_CONSTRAINTS')
        if fire_triggers:
            with_opts.append('FIRE_TRIGGERS')
        if keep_nulls:
            with_opts.append('KEEP_NULLS')
        if kb_per_batch:
            with_opts.append('KILOBYTES_PER_BATCH = {0}'.format(kb_per_batch))
        if rows_per_batch:
            with_opts.append('ROWS_PER_BATCH = {0}'.format(rows_per_batch))
        if order:
            with_opts.append('ORDER({0})'.format(','.join(order)))
        if tablock:
            with_opts.append('TABLOCK')
        with_part = ''
        if with_opts:
            with_part = 'WITH ({0})'.format(','.join(with_opts))
        operation = 'INSERT BULK {0}({1}) {2}'.format(obj_name, col_defs, with_part)
        self.execute(operation)
        self._session.submit_bulk(metadata, rows)
        self._session.process_simple_request()


class _MarsCursor(Cursor):
    def _assert_open(self):
        conn = self._conn
        if conn is not None:
            conn = conn()
        if not conn:
            raise InterfaceError('Cursor is closed')
        conn._assert_open()
        if not self._session.is_connected():
            self._session = conn._conn.create_session(self._tzinfo_factory)
        return conn

    @property
    def spid(self):
        # not thread safe for connection
        conn = self._assert_open()
        dirty = conn._dirty
        spid = self.execute_scalar('select @@SPID')
        conn._dirty = dirty
        return spid

    def cancel(self):
        self._assert_open()
        self._session.cancel_if_pending()

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        if self._session is not None:
            try:
                self._session.close()
                self._session = None
            except socket.error as e:
                if e.errno != errno.ECONNRESET:
                    raise

    def execute(self, operation, params=()):
        self._assert_open()
        self._execute(operation, params)
        # for compatibility with pyodbc
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
        return self._callproc(procname, parameters)

    def _begin_tran(self, isolation_level):
        self._assert_open()
        self._session.begin_tran(isolation_level=isolation_level)

    def _commit(self, cont, isolation_level=0):
        conn = self._assert_open()
        self._session.commit(cont=cont, isolation_level=isolation_level)
        conn._dirty = False

    def _rollback(self, cont, isolation_level=0):
        conn = self._assert_open()
        self._session.rollback(cont=cont, isolation_level=isolation_level)
        conn._dirty = False


def _resolve_instance_port(server, port, instance, timeout=5):
    if instance and not port:
        logger.info('querying %s for list of instances', server)
        instances = tds7_get_instances(server, timeout=timeout)
        if instance not in instances:
            raise LoginError("Instance {0} not found on server {1}".format(instance, server))
        instdict = instances[instance]
        if 'tcp' not in instdict:
            raise LoginError("Instance {0} doen't have tcp connections enabled".format(instance))
        port = int(instdict['tcp'])
    return port or 1433


def _parse_server(server):
    instance = ""
    if "\\" in server:
        server, instance = server.split("\\")

    # support MS methods of connecting locally
    if server in (".", "(local)"):
        server = "localhost"

    return server, instance.upper()


# map to servers deques, used to store active/passive servers
# between calls to connect function
# deques are used because they can be rotated
_servers_deques = {}


def _get_servers_deque(servers, database):
    """ Returns deque of servers for given tuple of servers and
    database name.
    This deque have active server at the begining, if first server
    is not accessible at the moment the deque will be rotated,
    second server will be moved to the first position, thirt to the
    second position etc, and previously first server will be moved
    to the last position.
    This allows to remember last successful server between calls
    to connect function.
    """
    key = (servers, database)
    if key not in _servers_deques:
        _servers_deques[key] = deque(servers)
    return _servers_deques[key]


def _parse_connection_string(connstr):
    """
    MSSQL style connection string parser

    Returns normalized dictionary of connection string parameters
    """
    res = {}
    for item in connstr.split(';'):
        item = item.strip()
        if not item:
            continue
        key, value = item.split('=', 1)
        key = key.strip().lower().replace(' ', '_')
        value = value.strip()
        res[key] = value
    return res


def connect(dsn=None, database=None, user=None, password=None, timeout=None,
            login_timeout=15, as_dict=None,
            appname=None, port=None, tds_version=tds_base.TDS74,
            autocommit=False,
            blocksize=4096, use_mars=False, auth=None, readonly=False,
            load_balancer=None, use_tz=None, bytes_to_unicode=True,
            row_strategy=None, failover_partner=None, server=None,
            cafile=None, sock=None, validate_host=True,
            enc_login_only=False, disable_connect_retry=False,
            pooling=False,
            use_sso=False,
            ):
    """
    Opens connection to the database

    :keyword dsn: SQL server host and instance: <host>[\\<instance>]
    :type dsn: string
    :keyword failover_partner: secondary database host, used if primary is not accessible
    :type failover_partner: string
    :keyword database: the database to initially connect to
    :type database: string
    :keyword user: database user to connect as
    :type user: string
    :keyword password: user's password
    :type password: string
    :keyword timeout: query timeout in seconds, default 0 (no timeout)
    :type timeout: int
    :keyword login_timeout: timeout for connection and login in seconds, default 15
    :type login_timeout: int
    :keyword as_dict: whether rows should be returned as dictionaries instead of tuples.
    :type as_dict: boolean
    :keyword appname: Set the application name to use for the connection
    :type appname: string
    :keyword port: the TCP port to use to connect to the server
    :type port: int
    :keyword tds_version: Maximum TDS version to use, should only be used for testing
    :type tds_version: int
    :keyword autocommit: Enable or disable database level autocommit
    :type autocommit: bool
    :keyword blocksize: Size of block for the TDS protocol, usually should not be used
    :type blocksize: int
    :keyword use_mars: Enable or disable MARS
    :type use_mars: bool
    :keyword auth: An instance of authentication method class, e.g. Ntlm or Sspi
    :keyword readonly: Allows to enable read-only mode for connection, only supported by MSSQL 2012,
      earlier versions will ignore this parameter
    :type readonly: bool
    :keyword load_balancer: An instance of load balancer class to use, if not provided will not use load balancer
    :keyword use_tz: Provides timezone for naive database times, if not provided date and time will be returned
      in naive format
    :keyword bytes_to_unicode: If true single byte database strings will be converted to unicode Python strings,
      otherwise will return strings as ``bytes`` without conversion.
    :type bytes_to_unicode: bool
    :keyword row_strategy: strategy used to create rows, determines type of returned rows, can be custom or one of:
      :func:`tuple_row_strategy`, :func:`list_row_strategy`, :func:`dict_row_strategy`,
      :func:`namedtuple_row_strategy`, :func:`recordtype_row_strategy`
    :type row_strategy: function of list of column names returning row factory
    :keyword cafile: Name of the file containing trusted CAs in PEM format, if provided will enable TLS
    :type cafile: str
    :keyword validate_host: Host name validation during TLS connection is enabled by default, if you disable it you
      will be vulnerable to MitM type of attack.
    :type validate_host: bool
    :keyword enc_login_only: Allows you to scope TLS encryption only to an authentication portion.  This means that
      anyone who can observe traffic on your network will be able to see all your SQL requests and potentially modify
      them.
    :type enc_login_only: bool
    :keyword use_sso: Enables SSO login, e.g. Kerberos using SSPI on Windows and kerberos package on other platforms.
             Cannot be used together with auth parameter.
    :returns: An instance of :class:`Connection`
    """
    if use_sso and auth:
        raise ValueError('use_sso cannot be used with auth parameter defined')
    login = _TdsLogin()
    login.client_host_name = socket.gethostname()[:128]
    login.library = "Python TDS Library"
    login.user_name = user or ''
    login.password = password or ''
    login.app_name = appname or 'pytds'
    login.port = port
    login.language = ''  # use database default
    login.attach_db_file = ''
    login.tds_version = tds_version
    if tds_version < tds_base.TDS70:
        raise ValueError('This TDS version is not supported')
    login.database = database or ''
    login.bulk_copy = False
    login.client_lcid = lcid.LANGID_ENGLISH_US
    login.use_mars = use_mars
    login.pid = os.getpid()
    login.change_password = ''
    login.client_id = uuid.getnode()  # client mac address
    login.cafile = cafile
    login.validate_host = validate_host
    login.enc_login_only = enc_login_only
    if cafile:
        if not tls.OPENSSL_AVAILABLE:
            raise ValueError("You are trying to use encryption but pyOpenSSL does not work, you probably "
                             "need to install it first")
        login.tls_ctx = tls.create_context(cafile)
        if login.enc_login_only:
            login.enc_flag = PreLoginEnc.ENCRYPT_OFF
        else:
            login.enc_flag = PreLoginEnc.ENCRYPT_ON
    else:
        login.tls_ctx = None
        login.enc_flag = PreLoginEnc.ENCRYPT_NOT_SUP

    if use_tz:
        login.client_tz = use_tz
    else:
        login.client_tz = pytds.tz.local

    # that will set:
    # ANSI_DEFAULTS to ON,
    # IMPLICIT_TRANSACTIONS to OFF,
    # TEXTSIZE to 0x7FFFFFFF (2GB) (TDS 7.2 and below), TEXTSIZE to infinite (introduced in TDS 7.3),
    # and ROWCOUNT to infinite
    login.option_flag2 = tds_base.TDS_ODBC_ON

    login.connect_timeout = login_timeout
    login.query_timeout = timeout
    login.blocksize = blocksize
    login.readonly = readonly
    login.load_balancer = load_balancer
    login.bytes_to_unicode = bytes_to_unicode

    if server and dsn:
        raise ValueError("Both server and dsn shouldn't be specified")

    if server:
        warnings.warn("server parameter is deprecated, use dsn instead", DeprecationWarning)
        dsn = server

    if load_balancer and failover_partner:
        raise ValueError("Both load_balancer and failover_partner shoudln't be specified")
    if load_balancer:
        servers = [(srv, None) for srv in load_balancer.choose()]
    else:
        servers = [(dsn or 'localhost', port)]
        if failover_partner:
            servers.append((failover_partner, port))

    parsed_servers = []
    for srv, port in servers:
        host, instance = _parse_server(srv)
        if instance and port:
            raise ValueError("Both instance and port shouldn't be specified")
        parsed_servers.append((host, port, instance))

    if use_sso:
        spn = "MSSQLSvc@{}:{}".format(parsed_servers[0][0], parsed_servers[0][1])
        from . import login as pytds_login
        try:
            login.auth = pytds_login.SspiAuth(spn=spn)
        except ImportError:
            login.auth = pytds_login.KerberosAuth(spn)
    else:
        login.auth = auth

    login.servers = _get_servers_deque(tuple(parsed_servers), database)

    # unique connection identifier used to pool connection
    key = (
        dsn,
        login.user_name,
        login.app_name,
        login.tds_version,
        login.database,
        login.client_lcid,
        login.use_mars,
        login.cafile,
        login.blocksize,
        login.readonly,
        login.bytes_to_unicode,
        login.auth,
        login.client_tz,
        autocommit,
    )

    conn = Connection()
    conn._use_tz = use_tz
    conn._autocommit = autocommit
    conn._login = login
    conn._pooling = pooling
    conn._key = key

    assert row_strategy is None or as_dict is None,\
        'Both row_startegy and as_dict were specified, you should use either one or another'
    if as_dict is not None:
        conn.as_dict = as_dict
    elif row_strategy is not None:
        conn._row_strategy = row_strategy
    else:
        conn._row_strategy = tuple_row_strategy # default row strategy

    conn._isolation_level = 0
    conn._dirty = False
    from .tz import FixedOffsetTimezone
    conn._tzinfo_factory = None if use_tz is None else FixedOffsetTimezone
    if disable_connect_retry:
        conn._try_open(timeout=login.connect_timeout, sock=sock)
    else:
        conn._open(sock=sock)
    return conn


def Date(year, month, day):
    return datetime.date(year, month, day)


def DateFromTicks(ticks):
    return datetime.date.fromtimestamp(ticks)


def Time(hour, minute, second, microsecond=0, tzinfo=None):
    return datetime.time(hour, minute, second, microsecond, tzinfo)


def TimeFromTicks(ticks):
    import time
    return Time(*time.localtime(ticks)[3:6])


def Timestamp(year, month, day, hour, minute, second, microseconds=0, tzinfo=None):
    return datetime.datetime(year, month, day, hour, minute, second, microseconds, tzinfo)


def TimestampFromTicks(ticks):
    return datetime.datetime.fromtimestamp(ticks)
