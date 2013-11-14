"""DB-SIG compliant module for communicating with MS SQL servers"""

__author__ = 'Mikhail Denisenko <denisenkom@gmail.com>'
__version__ = '1.6.3'

import logging
import six
import os
from six.moves import xrange
from . import lcid
from datetime import date, datetime, time
from dateutil.tz import tzlocal
import socket
import errno
import uuid
from .tds import (
    Error, LoginError, DatabaseError,
    InterfaceError, TimeoutError,
    TDS_PENDING, TDS74,
    TDS_ENCRYPTION_OFF, TDS_ODBC_ON, SimpleLoadBalancer,
    IS_TDS7_PLUS,
    _TdsSocket, tds7_get_instances, ClosedConnectionError,
    SP_EXECUTESQL, Column,
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
                self._conn = _TdsSocket(self._use_tz)
                self._conn.login(self._login, sock)
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
            self._main_cursor._begin_tran(isolation_level=self._isolation_level)

    def __init__(self, server='.', database='', user='', password='', timeout=0,
                 login_timeout=60, as_dict=False,
                 appname=None, port=None, tds_version=TDS74,
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
        login.database = database
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
            login.client_tz = tzlocal()

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
        self._use_tz = use_tz
        self._autocommit = autocommit
        self._login = login
        self._as_dict = as_dict
        self._isolation_level = 0
        self._dirty = False
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
            in_tran = self._conn.tds72_transaction
            if in_tran and self._dirty:
                return _MarsCursor(self, self._conn.create_session())
            else:
                try:
                    return _MarsCursor(self, self._conn.create_session())
                except socket.error as e:
                    if e.errno != errno.ECONNRESET:
                        raise
                except ClosedConnectionError:
                    pass
                self._assert_open()
                return _MarsCursor(self, self._conn.create_session())
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
        except socket.error as e:
            if e.errno in (errno.ENETRESET, errno.ECONNRESET):
                return
        except ClosedConnectionError:
            pass
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

    def _callproc(self, procname, parameters):
        results = list(parameters)
        parameters = self._session._convert_params(parameters)
        self._exec_with_retry(lambda: self._session.submit_rpc(procname, parameters, 0))
        self._session.process_rpc()
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
        """
        self._assert_open()
        self._conn._try_activate_cursor(self)
        return self._callproc(procname, parameters)

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

    def cancel(self):
        self._assert_open()
        self._conn._try_activate_cursor(self)
        self._session.send_cancel()
        self._session.process_cancel()

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

    def _execute(self, operation, params):
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
            params = self._session._convert_params(params)
            param_definition = ','.join(
                '{0} {1}'.format(p.column_name, p.type.get_declaration())
                for p in params)
            self._exec_with_retry(lambda: self._session.submit_rpc(
                SP_EXECUTESQL,
                [self._session.make_param('', operation), self._session.make_param('', param_definition)] + params,
                0))
        else:
            self._exec_with_retry(lambda: self._session.submit_plain_query(operation))
        self._session.find_result_or_done()

    def execute(self, operation, params=()):
        # Execute the query
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

    def copy_to(self, file, table_or_view, sep='\t', columns=None,
            check_constraints=False, fire_triggers=False, keep_nulls=False,
            kb_per_batch=None, rows_per_batch=None, order=None, tablock=False):
        import csv
        reader = csv.reader(file, delimiter=sep)
        if not columns:
            self.execute('select top 1 * from [{}] where 1<>1'.format(table_or_view))
            columns = [col[0] for col in self.description]
        metadata = [Column(name=col, type=self._session.long_string_type(), flags=Column.fNullable) for col in columns]
        col_defs = ','.join('{} {}'.format(col.column_name, col.type.get_declaration())
                            for col in metadata)
        with_opts = []
        if check_constraints:
            with_opts.append('CHECK_CONSTRAINTS')
        if fire_triggers:
            with_opts.append('FIRE_TRIGGERS')
        if keep_nulls:
            with_opts.append('KEEP_NULLS')
        if kb_per_batch:
            with_opts.append('KILOBYTES_PER_BATCH = {}'.format(kb_per_batch))
        if rows_per_batch:
            with_opts.append('ROWS_PER_BATCH = {}'.format(rows_per_batch))
        if order:
            with_opts.append('ORDER({})'.format(','.join(order)))
        if tablock:
            with_opts.append('TABLOCK')
        with_part = ''
        if with_opts:
            with_part = 'WITH ({})'.format(','.join(with_opts))
        operation = 'INSERT BULK [{}]({}) {}'.format(table_or_view, col_defs, with_part)
        self.execute(operation)
        self._session.submit_bulk(metadata, reader)
        self._session.process_simple_request()


class _MarsCursor(_Cursor):
    def _assert_open(self):
        if not self._conn:
            raise Error('Cursor is closed')
        self._conn._assert_open()
        if not self._session.is_connected():
            self._session = self._conn._conn.create_session()

    @property
    def spid(self):
        # not thread safe for connection
        dirty = self._conn._dirty
        spid = self.execute_scalar('select @@SPID')
        self._conn._dirty = dirty
        return spid

    def cancel(self):
        self._assert_open()
        self._session.send_cancel()
        self._session.process_cancel()

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


connect = _Connection


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
