# vim: set fileencoding=utf8 :
from dblib import *
import logging

logger = logging.getLogger(__name__)

PYMSSQL_DEBUG = False

# List to store the connection objects in
connection_object_list = list()

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

def err_handler(dbproc, severity, dberr, oserr,
        dberrstr, oserrstr):
    raise Exception('not converted')

def msg_handler(dbproc, msgno, msgstate,
        severity, msgtext, srvname, procname,
        line):
    raise Exception('not converted')


# Module attributes for configuring _mssql
login_timeout = 60

min_error_severity = 6

# Buffer size for large numbers
NUMERIC_BUF_SZ = 45

###########################
## Compatibility Aliases ##
###########################
def connect(*args, **kwargs):
    return MSSQLConnection(*args, **kwargs)

def clr_err(conn):
    if conn is not None:
        conn.last_msg_no = 0
        conn.last_msg_severity = 0
        conn.last_msg_state = 0
    else:
        _mssql_last_msg_no = 0
        _mssql_last_msg_severity = 0
        _mssql_last_msg_state = 0

def db_cancel(conn):
    if conn == None:
        return

    if conn.dbproc is None:
        return

    from query import tds_send_cancel
    from token import tds_process_cancel
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
        return 0x702
    #elif verstr == u'8.0':
    #    return 0x800
    else:
        raise MSSQLException('unrecognized tds version: %s' % verstr)

class MSSQLConnection(object):
    @property
    def connected(self):
        """
        True if the connection to a database is open.
        """
        return self._connected

    def __init__(self, server="localhost", user="sa", password="",
            charset='', database='', appname=None, port='1433', tds_version='7.1'):
        logger.debug("_mssql.MSSQLConnection.__cinit__()")
        self._connected = 0
        #self._charset = <char *>PyMem_Malloc(PYMSSQL_CHARSETBUFSIZE)
        #self._charset[0] = <char>0
        self.last_msg_str = ''
        #self.last_msg_srv = <char *>PyMem_Malloc(PYMSSQL_MSGSIZE)
        #self.last_msg_srv[0] = <char>0
        #self.last_msg_proc = <char *>PyMem_Malloc(PYMSSQL_MSGSIZE)
        #self.last_msg_proc[0] = <char>0
        self.column_names = None
        self.column_types = None

        #cdef LOGINREC *login
        #cdef RETCODE rtc
        #cdef char *_charset

        # support MS methods of connecting locally
        instance = ""
        if "\\" in server:
            server, instance = server.split("\\")

        if server in (".", "(local)"):
            server = "localhost"

        server = server + "\\" + instance if instance else server

        login = dblogin()
        #if login == NULL:
        #    raise MSSQLDriverException("Out of memory")

        appname = appname or "pymssql"

        login.tds_login.user_name = user
        login.tds_login.password = password
        login.tds_login.app = appname
        login.tds_login.tds_version = _tds_ver_str_to_constant(tds_version)

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

        # Add ourselves to the global connection list
        connection_object_list.append(self)

        # Set the character set name
        if charset:
            _charset = charset
            self._charset = _charset
            login.tds_login.charset = self._charset

        # Set the login timeout
        dbsetlogintime(login_timeout)

        # Connect to the server
        try:
            self.dbproc = dbopen(login, server)
            #self.dbproc.tds_socket = tds_connect(server, database, user, password,
            #        port=port,
            #        connect_timeout=login_timeout,
            #        app_name=appname,
            #        client_charset=charset if charset else 'utf8',
            #        tds_version=_tds_ver_str_to_constant(tds_version))
        except Exception:
            logger.exception("_mssql.MSSQLConnection.__init__() connection failed")
            connection_object_list.remove(self)
            maybe_raise_MSSQLDatabaseException(None)
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
        from tds import *
        from query import tds_submit_query
        from token import tds_process_tokens
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

    def convert_db_value(self, data, type, length):
        logger.debug("_mssql.MSSQLConnection.convert_db_value()")
        #cdef char buf[NUMERIC_BUF_SZ] # buffer in which we store text rep of bug nums
        #cdef int len
        #cdef long prevPrecision
        #cdef BYTE precision
        #cdef DBDATEREC di
        #cdef DBDATETIME dt
        #cdef DBCOL dbcol

        if type == SQLBIT:
            raise Exception('not implemented')
            #return bool(<int>(<DBBIT *>data)[0])

        elif type == SQLINT1:
            raise Exception('not implemented')
            #return int(<int>(<DBTINYINT *>data)[0])

        elif type == SQLINT2:
            raise Exception('not implemented')
            #return int(<int>(<DBSMALLINT *>data)[0])

        elif type == SQLINT4:
            return struct.unpack('<l', data)[0]
            #return int(<int>(<DBINT *>data)[0])

        elif type == SQLINT8:
            #return long(<PY_LONG_LONG>(<PY_LONG_LONG *>data)[0])
            raise Exception('not implemented')

        elif type == SQLFLT4:
            #return float(<float>(<DBREAL *>data)[0])
            raise Exception('not implemented')

        elif type == SQLFLT8:
            #return float(<double>(<DBFLT8 *>data)[0])
            raise Exception('not implemented')

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

        elif type == SQLDATETIM4:
            raise Exception('not implemented')
            #dbconvert(self.dbproc, type, data, -1, SQLDATETIME,
            #    <BYTE *>&dt, -1)
            #dbdatecrack(self.dbproc, &di, <DBDATETIME *><BYTE *>&dt)
            #return datetime.datetime(di.year, di.month, di.day,
            #    di.hour, di.minute, di.second, di.millisecond * 1000)

        elif type == SQLDATETIME:
            raise Exception('not implemented')
            #dbdatecrack(self.dbproc, &di, <DBDATETIME *>data)
            #return datetime.datetime(di.year, di.month, di.day,
            #    di.hour, di.minute, di.second, di.millisecond * 1000)

        elif type in (SQLVARCHAR, SQLCHAR, SQLTEXT):
            raise Exception('not implemented')
            #if strlen(self._charset):
            #    return (<char *>data)[:length].decode(self._charset)
            #else:
            #    return (<char *>data)[:length]

        elif type == SQLUUID and (PY_MAJOR_VERSION >= 2 and PY_MINOR_VERSION >= 5):
            raise Exception('not implemented')
            #return uuid.UUID(bytes_le=(<char *>data)[:length])

        else:
            raise Exception('not implemented')
            #return (<char *>data)[:length]

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
        from tds import *
        from token import tds_process_tokens
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

        rtc = dbnextrow(self.dbproc)

        self._rows_affected = self.dbproc.tds_socket.rows_affected

        if rtc == NO_MORE_ROWS:
            self.clear_metadata()
            self.last_dbresults = 0
            return None

        return self.get_row(rtc)[0]

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

            # Prepare the query buffer
            dbcmd(self.dbproc, query_string)

            # Execute the query
            rtc = dbsqlexec(self.dbproc)
            check_cancel_and_raise(rtc, self)
        finally:
            logger.debug("_mssql.MSSQLConnection.format_and_run_query() END")

    def get_result(self):
        logger.debug("_mssql.MSSQLConnection.get_result() BEGIN")

        try:
            if self.last_dbresults:
                logger.debug("_mssql.MSSQLConnection.get_result(): last_dbresults == True, return None")
                return None

            self.clear_metadata()

            # Since python doesn't have a do/while loop do it this way
            while True:
                self.last_dbresults = dbresults(self.dbproc)
                self.num_columns = dbnumcols(self.dbproc)
                if self.last_dbresults != SUCCEED or self.num_columns > 0:
                    break
            check_cancel_and_raise(self.last_dbresults, self)

            self._rows_affected = dbcount(self.dbproc)

            if self.last_dbresults == NO_MORE_RESULTS:
                self.num_columns = 0
                logger.debug("_mssql.MSSQLConnection.get_result(): NO_MORE_RESULTS, return None")
                return None

            self.num_columns = dbnumcols(self.dbproc)

            logger.debug("_mssql.MSSQLConnection.get_result(): num_columns = %d", self.num_columns)

            column_names = list()
            column_types = list()

            for col in xrange(1, self.num_columns + 1):
                column_names.append(dbcolname(self.dbproc, col))
                coltype = dbcoltype(self.dbproc, col)
                column_types.append(get_api_coltype(coltype))

            self.column_names = tuple(column_names)
            self.column_types = tuple(column_types)
        finally:
            logger.debug("_mssql.MSSQLConnection.get_result() END")

    def get_row(self, row_info):
        dbproc = self.dbproc
        logger.debug("_mssql.MSSQLConnection.get_row()")
        global _row_count

        if PYMSSQL_DEBUG:
            _row_count += 1

        record = tuple()

        for col in xrange(1, self.num_columns + 1):

            data = get_data(dbproc, row_info, col)
            col_type = get_type(dbproc, row_info, col)
            len = get_length(dbproc, row_info, col)

            if data == None:
                record += (None,)
                continue

            if PYMSSQL_DEBUG:
                fprintf(stderr, 'Processing row %d, column %d,' \
                    'Got data=%x, coltype=%d, len=%d\n', _row_count, col,
                    data, col_type, len)

            record += (self.convert_db_value(data, col_type, len),)
        return record

def assert_connected(conn):
    logger.debug("_mssql.assert_connected()")
    if not conn.connected:
        raise MSSQLDriverException("Not connected to any MS SQL server")


def get_data(dbproc, row_info, col):
    return dbdata(dbproc, col) if row_info == REG_ROW else \
        dbadata(dbproc, row_info, col)

def get_type(dbproc, row_info, col):
    return dbcoltype(dbproc, col) if row_info == REG_ROW else \
        dbalttype(dbproc, row_info, col)

def get_length(dbproc, row_info, col):
    return dbdatlen(dbproc, col) if row_info == REG_ROW else \
        dbadlen(dbproc, row_info, col)

def check_and_raise(rtc, conn):
    pass
    #if rtc == FAIL:
    #    return maybe_raise_MSSQLDatabaseException(conn)
    #elif get_last_msg_str(conn):
    #    return maybe_raise_MSSQLDatabaseException(conn)

def check_cancel_and_raise(rtc, conn):
    if rtc == FAIL:
        db_cancel(conn)
        return maybe_raise_MSSQLDatabaseException(conn)
    elif get_last_msg_str(conn):
        return maybe_raise_MSSQLDatabaseException(conn)

def get_last_msg_str(conn):
    return conn.last_msg_str if conn != None else _mssql_last_msg_str

def init_mssql():
    dbinit()
    dberrhandle(err_handler)
    dbmsghandle(msg_handler)

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

init_mssql()

if __name__ == '__main__':
    logging.basicConfig(level='DEBUG')
    #conn = connect(server='localhost', database=u'Учет', user='voroncova', password='voroncova', tds_version='7.0')
    conn = connect(server='subportal_dev', database=u'SubmissionPortal', user='sra_sa', password='sra_sa_pw', tds_version='7.0', charset='utf8')
    assert 5 == conn.execute_scalar('select 5 as fieldname')
    assert 'text' == conn.execute_scalar("select 'test' as fieldname")
