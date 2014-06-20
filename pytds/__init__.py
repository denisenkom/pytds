"""DB-SIG compliant module for communicating with MS SQL servers"""

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = '1.7.0'

import logging
import six
import os
import re
import keyword
from six.moves import xrange
from . import lcid
from datetime import date, datetime, time
from . import tz
import socket
import errno
import uuid
import warnings
from .tds import *
from .tds import (
    Error, LoginError, DatabaseError,
    InterfaceError, TimeoutError, OperationalError,
    TDS_PENDING, TDS74,
    TDS_ENCRYPTION_OFF, TDS_ODBC_ON, SimpleLoadBalancer,
    IS_TDS7_PLUS,
    _TdsSocket, tds7_get_instances, ClosedConnectionError,
    SP_EXECUTESQL, Column, _create_exception_by_message,
)

def _ver_to_int(ver):
    maj, minor, rev = ver.split('.')
    return (int(maj) << 24) + (int(minor) << 16) + (int(rev) << 8)

intversion = _ver_to_int(__version__)

logger = logging.getLogger(__name__)

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
    import recordtype  # optional dependency
    # replace empty column names with placeholders
    column_names = [name if is_valid_identifier(name) else 'col%s_' % idx for idx, name in enumerate(column_names)]
    recordtype_row_class = recordtype.recordtype('Row', column_names)

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


class Connection(object):
    """Connection object, this object should be created by calling :func:`connect`"""

    def __init__(self):
        self._closed = False
        self._conn = None

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
        """Isolation level for transactions"""
        return self._isolation_level

    def set_isolation_level(self, level):
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
    def chunk_handler(self):
        """
        Returns current chunk handler
        Default is MemoryChunkedHandler()
        """
        self._assert_open()
        return self._conn.chunk_handler

    @chunk_handler.setter
    def chunk_handler(self, value):
        self._assert_open()
        self._conn.chunk_handler = value

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

    def _open(self):
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
        err = None
        for host in login.load_balancer.choose():
            try:
                sock = socket.create_connection(
                    (host, login.port),
                    connect_timeout or 90000)
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            except socket.error as e:
                err = LoginError("Cannot connect to server '{0}': {1}".format(host, e), e)
                continue
            try:
                self._conn = _TdsSocket(self._use_tz)
                self._conn.login(self._login, sock, self._tzinfo_factory)
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
        sock.settimeout(login.query_timeout)
        self._active_cursor = self._main_cursor = self.cursor()
        if not self._autocommit:
            self._main_cursor._begin_tran(isolation_level=self._isolation_level)

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
                return _MarsCursor(self,
                                   self._conn.create_session(self._tzinfo_factory),
                                   self._tzinfo_factory)
            else:
                try:
                    return _MarsCursor(self,
                                       self._conn.create_session(self._tzinfo_factory),
                                       self._tzinfo_factory)
                except socket.error as e:
                    if e.errno != errno.ECONNRESET:
                        raise
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
            if e.errno in (errno.ENETRESET, errno.ECONNRESET):
                return
            raise
        except ClosedConnectionError:
            pass
        except OperationalError as e:
            # ignore ROLLBACK TRANSACTION without BEGIN TRANSACTION
            if e.number == 3903:
                return
            raise

    def __del__(self):
        if self._conn is not None:
            self._conn.close()

    def close(self):
        """ Close connection to an MS SQL Server.

        This function tries to close the connection and free all memory used.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        if self._conn:
            self._conn.close()
            self._conn = None
        self._closed = True

    def _try_activate_cursor(self, cursor):
        if cursor is not self._active_cursor:
            session = self._active_cursor._session
            if session.in_cancel:
                session.process_cancel()

            if session.state == TDS_PENDING:
                raise InterfaceError('Results are still pending on connection')
            self._active_cursor = cursor


class Cursor(six.Iterator):
    """
    This class represents a database cursor, which is used to issue queries
    and fetch results from a database connection.
    """
    def __init__(self, conn, session, tzinfo_factory):
        self._conn = conn
        self.arraysize = 1
        self._session = session
        self._tzinfo_factory = tzinfo_factory

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

    def _setup_row_factory(self):
        self._row_factory = None
        if self._session.res_info:
            column_names = [col[0] for col in self._session.res_info.description]
            self._row_factory = self._conn._row_strategy(column_names)

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
        return self._conn

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
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.cancel_if_pending()

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        if self._conn is not None:
            if self is self._conn._active_cursor:
                self._conn._active_cursor = self._conn._main_cursor
                self._session = None
            self._conn = None

    def _exec_with_retry(self, fun):
        self._assert_open()
        in_tran = self._conn._conn.tds72_transaction
        if in_tran and self._conn._dirty:
            self._conn._dirty = True
            return fun()
        else:
            self._conn._dirty = True
            try:
                return fun()
            except socket.error as e:
                if e.errno != errno.ECONNRESET:
                    raise
            except ClosedConnectionError:
                pass
            # in case of connection reset try again
            self._assert_open()
            return fun()

    def _ensure_transaction(self):
        if not self._conn._autocommit and not self._conn._conn.tds72_transaction:
            self._conn._main_cursor._begin_tran(isolation_level=self._conn._isolation_level)

    def _execute(self, operation, params):
        self._ensure_transaction()
        operation = six.text_type(operation)
        if params:
            if isinstance(params, (list, tuple)):
                names = []
                pid = 1
                named_params = {}
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
                named_params = {}
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
                    SP_EXECUTESQL,
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
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._execute(operation, params)

    def _begin_tran(self, isolation_level):
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.begin_tran(isolation_level=isolation_level)

    def _commit(self, cont, isolation_level=0):
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.commit(cont=cont, isolation_level=isolation_level)
        self._conn._dirty = False

    def _rollback(self, cont, isolation_level=0):
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.rollback(cont=cont, isolation_level=isolation_level)
        self._conn._dirty = False

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

    @property
    def messages(self):
        """ Messages generated by server, see http://legacy.python.org/dev/peps/pep-0249/#cursor-messages
        """
        #warnings.warn('DB-API extension cursor.messages used')
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
        for i in xrange(size):
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

    def copy_to(self, file, table_or_view, sep='\t', columns=None,
                check_constraints=False, fire_triggers=False, keep_nulls=False,
                kb_per_batch=None, rows_per_batch=None, order=None, tablock=False):
        """ *Experimental*. Efficiently load data to database from file using ``BULK INSERT`` operation

        :param file: Source file-like object, should be in csv format
        :param table_or_view: Destination table or view in the database
        :type table_or_view: str

        Optional parameters:

        :keyword sep: Separator used in csv file
        :type sep: str
        :keyword columns: List of column names in target table to insert to,
          if not provided will insert into all columns
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
        """
        import csv
        reader = csv.reader(file, delimiter=sep)
        if not columns:
            self.execute('select top 1 * from [{}] where 1<>1'.format(table_or_view))
            columns = [col[0] for col in self.description]
        metadata = [Column(name=col, type=self._conn._conn.NVarChar(4000), flags=Column.fNullable) for col in columns]
        col_defs = ','.join('{0} {1}'.format(col.column_name, col.type.get_declaration())
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
        operation = 'INSERT BULK [{0}]({1}) {2}'.format(table_or_view, col_defs, with_part)
        self.execute(operation)
        self._session.submit_bulk(metadata, reader)
        self._session.process_simple_request()


class _MarsCursor(Cursor):
    def _assert_open(self):
        if not self._conn:
            raise Error('Cursor is closed')
        self._conn._assert_open()
        if not self._session.is_connected():
            self._session = self._conn._conn.create_session(self._tzinfo_factory)

    @property
    def spid(self):
        # not thread safe for connection
        dirty = self._conn._dirty
        spid = self.execute_scalar('select @@SPID')
        self._conn._dirty = dirty
        return spid

    def cancel(self):
        self._assert_open()
        self._session.cancel_if_pending()

    def close(self):
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        if self._conn is not None:
            try:
                self._session.close()
            except socket.error as e:
                if e.errno != errno.ECONNRESET:
                    raise
            self._conn = None

    def execute(self, operation, params=()):
        self._assert_open()
        self._execute(operation, params)

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
        self._assert_open()
        self._session.commit(cont=cont, isolation_level=isolation_level)
        self._conn._dirty = False

    def _rollback(self, cont, isolation_level=0):
        self._assert_open()
        self._session.rollback(cont=cont, isolation_level=isolation_level)
        self._conn._dirty = False


def connect(server=None, database=None, user=None, password=None, timeout=None,
            login_timeout=60, as_dict=None,
            appname=None, port=None, tds_version=TDS74,
            encryption_level=TDS_ENCRYPTION_OFF, autocommit=False,
            blocksize=4096, use_mars=False, auth=None, readonly=False,
            load_balancer=None, use_tz=None, bytes_to_unicode=True,
            row_strategy=None):
    """
    Opens connection to the database

    :keyword server: database host
    :type server: string
    :keyword database: the database to initially connect to
    :type database: string
    :keyword user: database user to connect as
    :type user: string
    :keyword password: user's password
    :type password: string
    :keyword timeout: query timeout in seconds, default 0 (no timeout)
    :type timeout: int
    :keyword login_timeout: timeout for connection and login in seconds, default 60
    :type login_timeout: int
    :keyword as_dict: whether rows should be returned as dictionaries instead of tuples.
    :type as_dict: boolean
    :keyword appname: Set the application name to use for the connection
    :type appname: string
    :keyword port: the TCP port to use to connect to the server
    :type port: int
    :keyword tds_version: Maximum TDS version to use, should only be used for testing
    :type tds_version: int
    :keyword encryption_level: Encryption level to use, not supported
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
    :returns: An instance of :class:`Connection`
    """

    # support MS methods of connecting locally
    instance = ""
    if "\\" in server:
        server, instance = server.split("\\")

    if server in (".", "(local)"):
        server = "localhost"

    login = _TdsLogin()
    login.client_host_name = socket.gethostname()[:128]
    login.library = "Python TDS Library"
    login.encryption_level = encryption_level
    login.user_name = user or ''
    login.password = password or ''
    login.app_name = appname or 'pytds'
    login.port = port
    login.language = ''  # use database default
    login.attach_db_file = ''
    login.tds_version = tds_version
    login.database = database or ''
    login.bulk_copy = False
    login.text_size = 0
    login.client_lcid = lcid.LANGID_ENGLISH_US
    login.use_mars = use_mars
    login.pid = os.getpid()
    login.change_password = ''
    login.client_id = uuid.getnode()  # client mac address
    if use_tz:
        login.client_tz = use_tz
    else:
        login.client_tz = tz.local

    # that will set:
    # ANSI_DEFAULTS to ON,
    # IMPLICIT_TRANSACTIONS to OFF,
    # TEXTSIZE to 0x7FFFFFFF (2GB) (TDS 7.2 and below), TEXTSIZE to infinite (introduced in TDS 7.3),
    # and ROWCOUNT to infinite
    login.option_flag2 = TDS_ODBC_ON

    login.connect_timeout = login_timeout
    login.query_timeout = timeout
    login.server_name = server or '.'
    login.instance_name = instance.upper()  # to make case-insensitive comparison work this should be upper
    login.blocksize = blocksize
    login.auth = auth
    login.readonly = readonly
    login.load_balancer = load_balancer or SimpleLoadBalancer([server])
    login.bytes_to_unicode = bytes_to_unicode

    conn = Connection()
    conn._use_tz = use_tz
    conn._autocommit = autocommit
    conn._login = login

    assert row_strategy == None or as_dict == None, 'Both row_startegy and as_dict were specified, you should use either one or another'
    if as_dict != None:
        conn.as_dict = as_dict
    elif row_strategy != None:
        conn._row_strategy = row_strategy
    else:
        conn._row_strategy = tuple_row_strategy # default row strategy

    conn._isolation_level = 0
    conn._dirty = False
    from .tz import FixedOffsetTimezone
    conn._tzinfo_factory = None if use_tz is None else FixedOffsetTimezone
    conn._open()
    return conn


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
