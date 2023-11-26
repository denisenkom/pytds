"""DB-SIG compliant module for communicating with MS SQL servers"""
from __future__ import annotations

from collections import deque
import datetime
import os
import socket
import time
import uuid
import warnings
import weakref
import csv
import typing
from typing import Any
import collections.abc
from collections.abc import Iterable, Callable

from pytds.tds_types import NVarCharType, TzInfoFactoryType
from . import lcid
import pytds.tz
from .connection_pool import connection_pool, PoolKeyType
from .login import KerberosAuth, SspiAuth, AuthProtocol
from .row_strategies import tuple_row_strategy, list_row_strategy, dict_row_strategy, namedtuple_row_strategy, recordtype_row_strategy, RowGenerator, RowStrategy
from .tds import _TdsSocket, tds7_get_instances, _TdsLogin
from . import tds_base
from .tds_base import (
    Error,
    LoginError,
    DatabaseError,
    ProgrammingError,
    IntegrityError,
    DataError,
    InternalError,
    InterfaceError,
    TimeoutError,
    OperationalError,
    NotSupportedError,
    Warning,
    ClosedConnectionError,
    Column,
    PreLoginEnc,
    _create_exception_by_message,
)
from .tds_session import _TdsSession

from .tds_types import TableValuedParam, Binary

from .tds_base import (
    ROWID,
    DECIMAL,
    STRING,
    BINARY,
    NUMBER,
    DATETIME,
    INTEGER,
    REAL,
    XML,
    output,
    default,
)


from . import tls
import pkg_resources  # type: ignore # fix later

__author__ = "Mikhail Denisenko <denisenkom@gmail.com>"
try:
    __version__ = pkg_resources.get_distribution("python-tds").version
except:
    __version__ = "DEV"

from .tds_base import logger


def _ver_to_int(ver):
    res = ver.split(".")
    if len(res) < 2:
        logger.warning(
            'Invalid version {}, it should have 2 parts at least separated by "."'.format(
                ver
            )
        )
        return 0
    maj, minor, _ = ver.split(".")
    return (int(maj) << 24) + (int(minor) << 16)


intversion = _ver_to_int(__version__)

#: Compliant with DB SIG 2.0
apilevel = "2.0"

#: Module may be shared, but not connections
threadsafety = 1

#: This module uses extended python format codes
paramstyle = "pyformat"


class Cursor(typing.Protocol, Iterable):
    """
    This class defines an interface for cursor classes.
    It is implemented by MARS and non-MARS cursor classes.
    """

    def __enter__(self) -> Cursor:
        ...

    def __exit__(self, *args) -> None:
        ...

    def get_proc_outputs(self) -> list[typing.Any]:
        ...

    def callproc(
        self,
        procname: tds_base.InternalProc | str,
        parameters: dict[str, Any] | tuple[Any, ...] = (),
    ) -> list[Any]:
        ...

    @property
    def return_value(self) -> int | None:
        ...

    @property
    def spid(self) -> int:
        ...

    @property
    def connection(self) -> Connection | None:
        ...

    def get_proc_return_status(self) -> int | None:
        ...

    def cancel(self) -> None:
        ...

    def close(self) -> None:
        ...

    def execute(
        self,
        operation: str,
        params: list[Any] | tuple[Any, ...] | dict[str, Any] | None = (),
    ) -> Cursor:
        ...

    def executemany(
        self,
        operation: str,
        params_seq: Iterable[list[Any] | tuple[Any, ...] | dict[str, Any]],
    ) -> None:
        ...

    def execute_scalar(
        self,
        query_string: str,
        params: list[Any] | tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> Any:
        ...

    def nextset(self) -> bool | None:
        ...

    @property
    def rowcount(self) -> int:
        ...

    @property
    def description(self):
        ...

    def set_stream(self, column_idx: int, stream) -> None:
        ...

    @property
    def messages(
        self
    ) -> list[tuple[typing.Type, IntegrityError | ProgrammingError | OperationalError]] | None:
        ...

    @property
    def native_description(self):
        ...

    def fetchone(self) -> Any:
        ...

    def fetchmany(self, size=None) -> list[Any]:
        ...

    def fetchall(self) -> list[Any]:
        ...

    @staticmethod
    def setinputsizes(sizes=None) -> None:
        ...

    @staticmethod
    def setoutputsize(size=None, column=0) -> None:
        ...

    def copy_to(
        self,
        file: Iterable[str] | None = None,
        table_or_view: str | None = None,
        sep: str = "\t",
        columns: Iterable[Column | str] | None = None,
        check_constraints: bool = False,
        fire_triggers: bool = False,
        keep_nulls: bool = False,
        kb_per_batch: int | None = None,
        rows_per_batch: int | None = None,
        order: str | None = None,
        tablock: bool = False,
        schema: str | None = None,
        null_string: str | None = None,
        data: Iterable[tuple[Any, ...]] | None = None,
    ):
        ...


class Connection(typing.Protocol):
    """
    This class defines interface for connection object according to DBAPI specification.
    This interface is implemented by MARS and non-MARS connection classes.
    """

    @property
    def autocommit(self) -> bool:
        ...

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        ...

    @property
    def isolation_level(self) -> int:
        ...

    @isolation_level.setter
    def isolation_level(self, level: int) -> None:
        ...

    def __enter__(self) -> BaseConnection:
        ...

    def __exit__(self, *args) -> None:
        ...

    def commit(self) -> None:
        ...

    def rollback(self) -> None:
        ...

    def close(self) -> None:
        ...

    @property
    def mars_enabled(self) -> bool:
        ...

    def cursor(self) -> Cursor:
        ...


class BaseConnection(Connection):
    """
    Base connection class.  It implements most of the common logic for
    MARS and non-MARS connection classes.
    """

    _connection_closed_exception = InterfaceError("Connection closed")

    def __init__(
        self,
        pooling: bool,
        key: PoolKeyType,
        tds_socket: _TdsSocket,
    ) -> None:
        # _tds_socket is set to None when connection is closed
        self._tds_socket: _TdsSocket | None = tds_socket
        self._key = key
        self._pooling = pooling
        # references to all cursors opened from connection
        # those references used to close cursors when connection is closed
        self._cursors: weakref.WeakSet[Cursor] = weakref.WeakSet()

    @property
    def as_dict(self) -> bool:
        """
        Instructs all cursors this connection creates to return results
        as a dictionary rather than a tuple.
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        return self._tds_socket.main_session.row_strategy == dict_row_strategy

    @as_dict.setter
    def as_dict(self, value: bool) -> None:
        warnings.warn(
            "setting as_dict property on the active connection, instead create connection with needed row_strategy",
            DeprecationWarning,
        )
        if not self._tds_socket:
            raise self._connection_closed_exception
        if value:
            self._tds_socket.main_session.row_strategy = dict_row_strategy
        else:
            self._tds_socket.main_session.row_strategy = tuple_row_strategy

    @property
    def autocommit_state(self) -> bool:
        """
        An alias for `autocommit`, provided for compatibility with pymssql
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        return self._tds_socket.main_session.autocommit

    def set_autocommit(self, value: bool) -> None:
        """An alias for `autocommit`, provided for compatibility with ADO dbapi"""
        if not self._tds_socket:
            raise self._connection_closed_exception
        self._tds_socket.main_session.autocommit = value

    @property
    def autocommit(self) -> bool:
        """
        The current state of autocommit on the connection.
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        return self._tds_socket.main_session.autocommit

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        if not self._tds_socket:
            raise self._connection_closed_exception
        self._tds_socket.main_session.autocommit = value

    @property
    def isolation_level(self) -> int:
        """Isolation level for transactions,
        for possible values see :ref:`isolation-level-constants`

        .. seealso:: `SET TRANSACTION ISOLATION LEVEL`__ in MSSQL documentation

            .. __: http://msdn.microsoft.com/en-us/library/ms173763.aspx
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        return self._tds_socket.main_session.isolation_level

    @isolation_level.setter
    def isolation_level(self, level: int) -> None:
        if not self._tds_socket:
            raise self._connection_closed_exception
        self._tds_socket.main_session.isolation_level = level

    @property
    def tds_version(self) -> int:
        """
        Version of the TDS protocol that is being used by this connection
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        return self._tds_socket.tds_version

    @property
    def product_version(self):
        """
        Version of the MSSQL server
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        return self._tds_socket.product_version

    def __enter__(self) -> BaseConnection:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def commit(self) -> None:
        """
        Commit transaction which is currently in progress.
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        # Setting cont to True to start new transaction
        # after current transaction is rolled back
        self._tds_socket.main_session.commit(cont=True)

    def rollback(self) -> None:
        """
        Roll back transaction which is currently in progress.
        """
        if self._tds_socket:
            # Setting cont to True to start new transaction
            # after current transaction is rolled back
            self._tds_socket.main_session.rollback(cont=True)

    def close(self) -> None:
        """Close connection to an MS SQL Server.

        This function tries to close the connection and free all memory used.
        It can be called more than once in a row. No exception is raised in
        this case.
        """
        if self._tds_socket:
            logger.debug("Closing connection")
            if self._pooling:
                connection_pool.add(
                    self._key, (self._tds_socket, self._tds_socket.main_session)
                )
            else:
                self._tds_socket.close()
            logger.debug("Closing all cursors which were opened by connection")
            for cursor in self._cursors:
                cursor.close()
            self._tds_socket = None


class MarsConnection(BaseConnection):
    """
    MARS connection class, this object is created by calling :func:`connect`
    with use_mars parameter set to False.
    """

    def __init__(self, pooling: bool, key: PoolKeyType, tds_socket: _TdsSocket):
        super().__init__(pooling=pooling, key=key, tds_socket=tds_socket)

    @property
    def mars_enabled(self) -> bool:
        return True

    def cursor(self) -> _MarsCursor:
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        cursor = _MarsCursor(
            connection=self,
            session=self._tds_socket.create_session(),
        )
        self._cursors.add(cursor)
        return cursor

    def close(self):
        if self._tds_socket:
            self._tds_socket.close_all_mars_sessions()
        super().close()


class NonMarsConnection(BaseConnection):
    """
    Non-MARS connection class, this object should be created by calling :func:`connect`
    with use_mars parameter set to False.
    """

    def __init__(self, pooling: bool, key: PoolKeyType, tds_socket: _TdsSocket):
        super().__init__(pooling=pooling, key=key, tds_socket=tds_socket)
        self._active_cursor: NonMarsCursor | None = None

    @property
    def mars_enabled(self) -> bool:
        return False

    def cursor(self) -> NonMarsCursor:
        """
        Return cursor object that can be used to make queries and fetch
        results from the database.
        """
        if not self._tds_socket:
            raise self._connection_closed_exception
        # Only one cursor can be active at any given time
        if self._active_cursor:
            self._active_cursor.cancel()
            self._active_cursor.close()
        cursor = NonMarsCursor(
            connection=self,
            session=self._tds_socket.main_session,
        )
        self._active_cursor = cursor
        self._cursors.add(cursor)
        return cursor


class BaseCursor(Cursor, collections.abc.Iterator):
    """
    This class represents a base database cursor, which is used to issue queries
    and fetch results from a database connection.
    There are two actual cursor classes: one for MARS connections and one
    for non-MARS connections.
    """

    _cursor_closed_exception = InterfaceError("Cursor is closed")

    def __init__(self, connection: Connection, session: _TdsSession):
        self.arraysize = 1
        # Null value in _session means cursor was closed
        self._session: _TdsSession | None = session
        # Keeping strong reference to connection to prevent connection from being garbage collected
        # while there are active cursors
        self._connection: Connection | None = connection

    @property
    def connection(self) -> Connection | None:
        warnings.warn(
            "connection property is deprecated on the cursor object and will be removed in future releases",
            DeprecationWarning,
        )
        return self._connection

    def __enter__(self) -> BaseCursor:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __iter__(self) -> BaseCursor:
        """
        Return self to make cursors compatibile with Python iteration
        protocol.
        """
        return self

    def get_proc_outputs(self) -> list[Any]:
        """
        If stored procedure has result sets and OUTPUT parameters use this method
        after you processed all result sets to get values of the OUTPUT parameters.
        :return: A list of output parameter values.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        return self._session.get_proc_outputs()

    def callproc(
        self,
        procname: tds_base.InternalProc | str,
        parameters: dict[str, Any] | tuple[Any, ...] = (),
    ) -> list[Any]:
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
        if self._session is None:
            raise self._cursor_closed_exception
        return self._session.callproc(procname, parameters)

    @property
    def return_value(self) -> int | None:
        """Alias to :func:`get_proc_return_status`"""
        return self.get_proc_return_status()

    @property
    def spid(self) -> int:
        """MSSQL Server's session ID (SPID)

        It can be used to correlate connections between client and server logs.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        return self._session._spid

    def _get_tzinfo_factory(self) -> TzInfoFactoryType | None:
        if self._session is None:
            raise self._cursor_closed_exception
        return self._session.tzinfo_factory

    def _set_tzinfo_factory(self, tzinfo_factory: TzInfoFactoryType | None) -> None:
        if self._session is None:
            raise self._cursor_closed_exception
        self._session.tzinfo_factory = tzinfo_factory

    tzinfo_factory = property(_get_tzinfo_factory, _set_tzinfo_factory)

    def get_proc_return_status(self) -> int | None:
        """Last executed stored procedure's return value

        Returns integer value returned by `RETURN` statement from last executed stored procedure.
        If no value was not returned or no stored procedure was executed return `None`.
        """
        if self._session is None:
            return None
        return self._session.get_proc_return_status()

    def cancel(self) -> None:
        """Cancel currently executing statement or stored procedure call"""
        if self._session is None:
            return
        self._session.cancel_if_pending()

    def close(self) -> None:
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        logger.debug("Closing cursor")
        self._session = None
        self._connection = None

    T = typing.TypeVar("T")

    def execute(
        self,
        operation: str,
        params: list[Any] | tuple[Any, ...] | dict[str, Any] | None = (),
    ) -> BaseCursor:
        """Execute an SQL query

        Optionally query can be executed with parameters.
        To make parametrized query use `%s` in the query to denote a parameter
        and pass a tuple with parameter values, e.g.:

        .. code-block::

           execute("select %s, %s", (1,2))

        This will execute query replacing first `%s` with first parameter value - 1,
        and second `%s` with second parameter value -2.

        Another option is to use named parameters with passing a dictionary, e.g.:

        .. code-block::

           execute("select %(param1)s, %(param2)s", {param1=1, param2=2})

        Both those ways of passing parameters is safe from SQL injection attacks.

        This function does not return results of the execution.
        Use :func:`fetchone` or similar to fetch results.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        self._session.execute(operation, params)
        # for compatibility with pyodbc
        return self

    def executemany(
        self,
        operation: str,
        params_seq: Iterable[list[Any] | tuple[Any, ...] | dict[str, Any]],
    ) -> None:
        """
        Execute same SQL query multiple times for each parameter set in the `params_seq` list.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        self._session.executemany(operation=operation, params_seq=params_seq)

    def execute_scalar(
        self,
        query_string: str,
        params: list[Any] | tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> Any:
        """
        This method executes SQL query then returns first column of first row or the
        result.

        Query can be parametrized, see :func:`execute` method for details.

        This method is useful if you want just a single value, as in:

        .. code-block::

           conn.execute_scalar('SELECT COUNT(*) FROM employees')

        This method works in the same way as ``iter(conn).next()[0]``.
        Remaining rows, if any, can still be iterated after calling this
        method.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        return self._session.execute_scalar(query_string, params)

    def nextset(self) -> bool | None:
        """Move to next recordset in batch statement, all rows of current recordset are
        discarded if present.

        :returns: true if successful or ``None`` when there are no more recordsets
        """
        if self._session is None:
            raise self._cursor_closed_exception
        return self._session.next_set()

    @property
    def rowcount(self) -> int:
        """Number of rows affected by previous statement

        :returns: -1 if this information was not supplied by the server
        """
        if self._session is None:
            return -1
        return self._session.rows_affected

    @property
    def description(self):
        """Cursor description, see http://legacy.python.org/dev/peps/pep-0249/#description"""
        if self._session is None:
            return None
        res = self._session.res_info
        if res:
            return res.description
        else:
            return None

    def set_stream(self, column_idx: int, stream) -> None:
        """
        This function can be used to efficiently receive values which can be very large, e.g. `TEXT`, `VARCHAR(MAX)`, `VARBINARY(MAX)`.

        When streaming is not enabled, values are loaded to memory as they are received from server and
        once entire row is loaded, it is returned.

        With this function streaming receiver can be specified via `stream` parameter which will receive chunks of the data
        as they are received. For each received chunk driver will call stream's write method.
        For example this can be used to save value of a field into a file, or to
        proces value as it is being received.

        For string fields chunks are represented as unicode strings.
        For binary fields chunks are represented as `bytes` strings.

        Example usage:

        .. code-block::

           cursor.execute("select N'very large field'")
           cursor.set_stream(0, StringIO())
           row = cursor.fetchone()
           # now row[0] contains instance of a StringIO object which was gradually
           # filled with output from server for first column.

        :param column_idx: Zero based index of a column for which to setup streaming receiver
        :type column_idx: int
        :param stream: Stream object that will be receiving chunks of data via it's `write` method.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        res_info = self._session.res_info
        if not res_info:
            raise ValueError("No result set is active")
        if len(res_info.columns) <= column_idx or column_idx < 0:
            raise ValueError("Invalid value for column_idx")
        res_info.columns[column_idx].serializer.set_chunk_handler(
            pytds.tds_types._StreamChunkedHandler(stream)
        )

    @property
    def messages(
        self
    ) -> list[tuple[typing.Type, IntegrityError | ProgrammingError | OperationalError]] | None:
        """Messages generated by server, see http://legacy.python.org/dev/peps/pep-0249/#cursor-messages"""
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
        """todo document"""
        if self._session is None:
            return None
        res = self._session.res_info
        if res:
            return res.native_descr
        else:
            return None

    def fetchone(self) -> Any:
        """Fetch next row.

        Returns row using currently configured factory, or ``None`` if there are no more rows
        """
        if self._session is None:
            raise self._cursor_closed_exception
        return self._session.fetchone()

    def fetchmany(self, size=None) -> list[Any]:
        """Fetch next N rows

        :param size: Maximum number of rows to return, default value is cursor.arraysize
        :returns: List of rows
        """
        if self._session is None:
            raise self._cursor_closed_exception
        if size is None:
            size = self.arraysize

        rows = []
        for _ in range(size):
            row = self.fetchone()
            if not row:
                break
            rows.append(row)
        return rows

    def fetchall(self) -> list[Any]:
        """Fetch all remaining rows

        Do not use this if you expect large number of rows returned by the server,
        since this method will load all rows into memory.  It is more efficient
        to load and process rows by iterating over them.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        return list(row for row in self)

    def __next__(self) -> Any:
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    @staticmethod
    def setinputsizes(sizes=None) -> None:
        """
        This method does nothing, as permitted by DB-API specification.
        """
        pass

    @staticmethod
    def setoutputsize(size=None, column=0) -> None:
        """
        This method does nothing, as permitted by DB-API specification.
        """
        pass

    def copy_to(
        self,
        file: Iterable[str] | None = None,
        table_or_view: str | None = None,
        sep: str = "\t",
        columns: Iterable[Column | str] | None = None,
        check_constraints: bool = False,
        fire_triggers: bool = False,
        keep_nulls: bool = False,
        kb_per_batch: int | None = None,
        rows_per_batch: int | None = None,
        order: str | None = None,
        tablock: bool = False,
        schema: str | None = None,
        null_string: str | None = None,
        data: Iterable[collections.abc.Sequence[Any]] | None = None,
    ):
        """*Experimental*. Efficiently load data to database from file using ``BULK INSERT`` operation

        :param file: Source file-like object, should be in csv format. Specify
          either this or data, not both.
        :param table_or_view: Destination table or view in the database
        :type table_or_view: str

        Optional parameters:

        :keyword sep: Separator used in csv file
        :type sep: str
        :keyword columns: List of :class:`pytds.tds_base.Column` objects or column names in target
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
          iterables of values. Specify either data parameter or file parameter but not both.
        """
        if self._session is None:
            raise self._cursor_closed_exception
        # conn = self._conn()
        rows: Iterable[collections.abc.Sequence[typing.Any]]
        if data is None:
            if file is None:
                raise ValueError("No data was specified via file or data parameter")
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
            obj_name = f"{tds_base.tds_quote_id(schema)}.{obj_name}"
        if columns:
            metadata = []
            for column in columns:
                if isinstance(column, Column):
                    metadata.append(column)
                else:
                    metadata.append(
                        Column(
                            name=column,
                            type=NVarCharType(size=4000),
                            flags=Column.fNullable,
                        )
                    )
        else:
            self.execute(f"select top 1 * from {obj_name} where 1<>1")
            metadata = [
                Column(
                    name=col[0],
                    type=NVarCharType(size=4000),
                    flags=Column.fNullable if col[6] else 0,
                )
                for col in self.description
            ]
        col_defs = ",".join(
            f"{tds_base.tds_quote_id(col.column_name)} {col.type.get_declaration()}"
            for col in metadata
        )
        with_opts = []
        if check_constraints:
            with_opts.append("CHECK_CONSTRAINTS")
        if fire_triggers:
            with_opts.append("FIRE_TRIGGERS")
        if keep_nulls:
            with_opts.append("KEEP_NULLS")
        if kb_per_batch:
            with_opts.append("KILOBYTES_PER_BATCH = {0}".format(kb_per_batch))
        if rows_per_batch:
            with_opts.append("ROWS_PER_BATCH = {0}".format(rows_per_batch))
        if order:
            with_opts.append("ORDER({0})".format(",".join(order)))
        if tablock:
            with_opts.append("TABLOCK")
        with_part = ""
        if with_opts:
            with_part = "WITH ({0})".format(",".join(with_opts))
        operation = "INSERT BULK {0}({1}) {2}".format(obj_name, col_defs, with_part)
        self.execute(operation)
        self._session.submit_bulk(metadata, rows)
        self._session.process_simple_request()


class NonMarsCursor(BaseCursor):
    """
    This class represents a non-MARS database cursor, which is used to issue queries
    and fetch results from a database connection.

    Non-MARS connections allow only one cursor to be active at a given time.
    """

    def __init__(self, connection: NonMarsConnection, session: _TdsSession):
        super().__init__(connection=connection, session=session)


class _MarsCursor(BaseCursor):
    """
    This class represents a MARS database cursor, which is used to issue queries
    and fetch results from a database connection.

    MARS connections allow multiple cursors to be active at the same time.
    """

    def __init__(self, connection: MarsConnection, session: _TdsSession):
        super().__init__(
            connection=connection,
            session=session,
        )

    @property
    def spid(self) -> int:
        # not thread safe for connection
        return self.execute_scalar("select @@SPID")

    def close(self) -> None:
        """
        Closes the cursor. The cursor is unusable from this point.
        """
        logger.debug("Closing MARS cursor")
        if self._session is not None:
            self._session.close()
            self._session = None
        self._connection = None


def _resolve_instance_port(
    server: Any, port: int, instance: str, timeout: float = 5
) -> int:
    if instance and not port:
        logger.info("querying %s for list of instances", server)
        instances = tds7_get_instances(server, timeout=timeout)
        if not instances:
            raise RuntimeError(
                "Querying list of instances failed, returned value has invalid format"
            )
        if instance not in instances:
            raise LoginError(
                "Instance {0} not found on server {1}".format(instance, server)
            )
        instdict = instances[instance]
        if "tcp" not in instdict:
            raise LoginError(
                "Instance {0} doen't have tcp connections enabled".format(instance)
            )
        port = int(instdict["tcp"])
    return port or 1433


def _parse_server(server: str) -> tuple[str, str]:
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
_servers_deques: dict[
    tuple[tuple[tuple[str, int | None, str], ...], str | None],
    deque[tuple[Any, int | None, str]],
] = {}


def _get_servers_deque(
    servers: tuple[tuple[str, int | None, str], ...], database: str | None
):
    """Returns deque of servers for given tuple of servers and
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


def _parse_connection_string(connstr: str) -> dict[str, str]:
    """
    MSSQL style connection string parser

    Returns normalized dictionary of connection string parameters
    """
    res = {}
    for item in connstr.split(";"):
        item = item.strip()
        if not item:
            continue
        key, value = item.split("=", 1)
        key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        res[key] = value
    return res


def connect(
    dsn: str | None = None,
    database: str | None = None,
    user: str | None = None,
    password: str | None = None,
    timeout: float | None = None,
    login_timeout: float = 15,
    as_dict: bool | None = None,
    appname: str | None = None,
    port: int | None = None,
    tds_version: int = tds_base.TDS74,
    autocommit: bool = False,
    blocksize: int = 4096,
    use_mars: bool = False,
    auth: AuthProtocol | None = None,
    readonly: bool = False,
    load_balancer: tds_base.LoadBalancer | None = None,
    use_tz: datetime.tzinfo | None = None,
    bytes_to_unicode: bool = True,
    row_strategy: RowStrategy | None = None,
    failover_partner: str | None = None,
    server: str | None = None,
    cafile: str | None = None,
    sock: socket.socket | None = None,
    validate_host: bool = True,
    enc_login_only: bool = False,
    disable_connect_retry: bool = False,
    pooling: bool = False,
    use_sso: bool = False,
    isolation_level: int = 0,
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
        raise ValueError("use_sso cannot be used with auth parameter defined")
    login = _TdsLogin()
    login.client_host_name = socket.gethostname()[:128]
    login.library = "Python TDS Library"
    login.user_name = user or ""
    login.password = password or ""
    login.app_name = appname or "pytds"
    login.port = port
    login.language = ""  # use database default
    login.attach_db_file = ""
    login.tds_version = tds_version
    if tds_version < tds_base.TDS70:
        raise ValueError("This TDS version is not supported")
    login.database = database or ""
    login.bulk_copy = False
    login.client_lcid = lcid.LANGID_ENGLISH_US
    login.use_mars = use_mars
    login.pid = os.getpid()
    login.change_password = ""
    login.client_id = uuid.getnode()  # client mac address
    login.cafile = cafile
    login.validate_host = validate_host
    login.enc_login_only = enc_login_only
    if cafile:
        if not tls.OPENSSL_AVAILABLE:
            raise ValueError(
                "You are trying to use encryption but pyOpenSSL does not work, you probably "
                "need to install it first"
            )
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
        warnings.warn(
            "server parameter is deprecated, use dsn instead", DeprecationWarning
        )
        dsn = server

    if load_balancer and failover_partner:
        raise ValueError(
            "Both load_balancer and failover_partner shoudln't be specified"
        )
    servers: list[tuple[str, int | None]] = []
    if load_balancer:
        servers += ((srv, None) for srv in load_balancer.choose())
    else:
        servers += [(dsn or "localhost", port)]
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

    from .tz import FixedOffsetTimezone

    tzinfo_factory = None if use_tz is None else FixedOffsetTimezone
    # conn = Connection(
    #    login_info=login,
    #    pooling=pooling,
    #    key=key,
    #    use_tz=use_tz,
    #    autocommit=autocommit,
    #    tzinfo_factory=tzinfo_factory
    # )

    assert (
        row_strategy is None or as_dict is None
    ), "Both row_startegy and as_dict were specified, you should use either one or another"
    if as_dict:
        row_strategy = dict_row_strategy
    elif row_strategy is not None:
        row_strategy = row_strategy
    else:
        row_strategy = tuple_row_strategy  # default row strategy

    if disable_connect_retry:
        first_try_time = login.connect_timeout
    else:
        first_try_time = login.connect_timeout * 0.08

    def attempt(attempt_timeout: float) -> BaseConnection:
        if pooling:
            res = connection_pool.take(key)
            if res is not None:
                tds_socket, sess = res
                sess.callproc("sp_reset_connection", [])
                tds_socket._row_strategy = row_strategy
                if tds_socket.mars_enabled:
                    return MarsConnection(
                        pooling=pooling,
                        key=key,
                        tds_socket=tds_socket,
                    )
                else:
                    return NonMarsConnection(
                        pooling=pooling,
                        key=key,
                        tds_socket=tds_socket,
                    )
        host, port, instance = login.servers[0]
        return _connect(
            login=login,
            host=host,
            port=port,
            instance=instance,
            timeout=attempt_timeout,
            pooling=pooling,
            key=key,
            autocommit=autocommit,
            isolation_level=isolation_level,
            tzinfo_factory=tzinfo_factory,
            sock=sock,
            use_tz=use_tz,
            row_strategy=row_strategy,
        )

    def ex_handler(ex: Exception) -> None:
        if isinstance(ex, LoginError):
            raise ex
        elif isinstance(ex, BrokenPipeError):
            # Allow to retry when BrokenPipeError is received
            pass
        elif isinstance(ex, OperationalError):
            # if there are more than one message this means
            # that the login was successful, like in the
            # case when database is not accessible
            # mssql returns 2 messages:
            # 1) Cannot open database "<dbname>" requested by the login. The login failed.
            # 2) Login failed for user '<username>'
            # in this case we want to retry
            if ex.msg_no in (
                18456,  # login failed
                18486,  # account is locked
                18487,  # password expired
                18488,  # password should be changed
                18452,  # login from untrusted domain
            ):
                raise ex
        else:
            raise ex

    return exponential_backoff(
        work=attempt,
        ex_handler=ex_handler,
        max_time_sec=login.connect_timeout,
        first_attempt_time_sec=first_try_time,
    )


def _connect(
    login: _TdsLogin,
    host: str,
    port: int,
    instance: str,
    timeout: float,
    pooling: bool,
    key: PoolKeyType,
    autocommit: bool,
    isolation_level: int,
    tzinfo_factory: TzInfoFactoryType | None,
    sock: socket.socket | None,
    use_tz: datetime.tzinfo | None,
    row_strategy: RowStrategy,
) -> BaseConnection:
    try:
        login.server_name = host
        login.instance_name = instance
        port = _resolve_instance_port(host, port, instance, timeout=timeout)
        if not sock:
            logger.info("Opening socket to %s:%d", host, port)
            sock = socket.create_connection((host, port), timeout)
    except Exception as e:
        raise LoginError(f"Cannot connect to server '{host}': {e}", e)

    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    # default keep alive should be 30 seconds according to spec:
    # https://msdn.microsoft.com/en-us/library/dd341108.aspx
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 30)

    sock.settimeout(timeout)
    tds_socket = _TdsSocket(
        sock=sock,
        tzinfo_factory=tzinfo_factory,
        use_tz=use_tz,
        row_strategy=row_strategy,
        autocommit=autocommit,
        login=login,
        isolation_level=isolation_level,
    )
    try:
        route = tds_socket.login()
        if route is not None:
            # rerouted to different server
            sock.close()
            ###  Change SPN once route exists
            from . import login as pytds_login

            if isinstance(login.auth, pytds_login.SspiAuth):
                route_spn = f"MSSQLSvc@{host}:{port}"
                login.auth = pytds_login.SspiAuth(
                    user_name=login.user_name,
                    password=login.password,
                    server_name=host,
                    port=port,
                    spn=route_spn,
                )

            return _connect(
                login=login,
                host=route["server"],
                port=route["port"],
                instance=instance,
                timeout=timeout,
                pooling=pooling,
                key=key,
                autocommit=autocommit,
                isolation_level=isolation_level,
                tzinfo_factory=tzinfo_factory,
                use_tz=use_tz,
                row_strategy=row_strategy,
                sock=None,
            )
        if not autocommit:
            tds_socket.main_session.begin_tran()
        sock.settimeout(login.query_timeout)
        if tds_socket.mars_enabled:
            return MarsConnection(
                pooling=pooling,
                key=key,
                tds_socket=tds_socket,
            )
        else:
            return NonMarsConnection(
                pooling=pooling,
                key=key,
                tds_socket=tds_socket,
            )
    except:
        sock.close()
        raise


T = typing.TypeVar("T")


def exponential_backoff(
    work: Callable[[float], T],
    ex_handler: Callable[[Exception], None],
    max_time_sec: float,
    first_attempt_time_sec: float,
    backoff_factor: float = 2,
) -> T:
    try_time = first_attempt_time_sec
    last_error: Exception | None
    end_time = time.time() + max_time_sec
    while True:
        try_start_time = time.time()
        try:
            return work(try_time)
        except Exception as ex:
            last_error = ex
            ex_handler(ex)
        if time.time() >= end_time:
            raise last_error or TimeoutError()
        remaining_attempt_time = try_time - (time.time() - try_start_time)
        if remaining_attempt_time > 0:
            time.sleep(remaining_attempt_time)
        try_time *= backoff_factor


def Date(year: int, month: int, day: int) -> datetime.date:
    return datetime.date(year, month, day)


def DateFromTicks(ticks: float) -> datetime.date:
    return datetime.date.fromtimestamp(ticks)


def Time(
    hour: int,
    minute: int,
    second: int,
    microsecond: int = 0,
    tzinfo: datetime.tzinfo | None = None,
) -> datetime.time:
    return datetime.time(hour, minute, second, microsecond, tzinfo)


def TimeFromTicks(ticks: float) -> datetime.time:
    import time

    return Time(*time.localtime(ticks)[3:6])


def Timestamp(
    year: int,
    month: int,
    day: int,
    hour: int,
    minute: int,
    second: int,
    microseconds: int = 0,
    tzinfo: datetime.tzinfo | None = None,
) -> datetime.datetime:
    return datetime.datetime(
        year, month, day, hour, minute, second, microseconds, tzinfo
    )


def TimestampFromTicks(ticks: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ticks)
