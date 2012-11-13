import logging
from tds import *
from mem import *
from threadsafe import *
from sybdb import *
from config import *
from login import *
from query import *

logger = logging.getLogger(__name__)

dblib_mutex = None

_DB_RES_INIT            = 0
_DB_RES_RESULTSET_EMPTY = 1
_DB_RES_RESULTSET_ROWS  = 2
_DB_RES_NEXT_RESULT     = 3
_DB_RES_NO_MORE_RESULTS = 4
_DB_RES_SUCCEED         = 5

REG_ROW         = -1
MORE_ROWS       = -1
NO_MORE_ROWS    = -2
BUF_FULL        = -3
NO_MORE_RESULTS = 2
SUCCEED         = 1
FAIL            = 0

def CHECK_CONN(conn):
    pass

#
# Return the current row buffer index.  
# We strive to validate it first.  It must be:
# 	between zero and capacity (obviously), and
# 	between the head and the tail, logically.  
#
# If the head has wrapped the tail, it shouldn't be in no man's land.  
# IOW, if capacity is 9, head is 3 and tail is 7, good rows are 7-8 and 0-2.
#      (Row 3 is about-to-be-inserted, and 4-6 are not in use.)  Here's a diagram:
# 		d d d ! ! ! ! d d
#		0 1 2 3 4 5 6 7 8
#		      ^       ^
#		      Head    Tail
#
# The special case is capacity == 1, meaning there's no buffering, and head == tail === 0.  
#
def buffer_current_index(dbproc):
    buf = dbproc.row_buf
    if buf.capacity <= 1: # no buffering
        return -1
    raise Exception('not implemented')
    #if (buf->current == buf->head || buf->current == buf->capacity)
    #        return -1;
    #        
    #assert(buf->current >= 0);
    #assert(buf->current < buf->capacity);
    #
    #if( buf->tail < buf->head) {
    #        assert(buf->tail < buf->current);
    #        assert(buf->current < buf->head);
    #} else {
    #        if (buf->current > buf->head)
    #                assert(buf->current > buf->tail);
    #}
    #return buf->current;

def buffer_set_capacity(dbproc, nrows):
    buf = dbproc.row_buf
    if nrows == 0:
        buf.capacity = 1
        return
    buf.capacity = nrows

def buffer_is_full(buf):
    #BUFFER_CHECK(buf)
    return buf.capacity == buffer_count(buf) and buf.capacity > 1

def buffer_free(dbproc):
    pass

def buffer_alloc(dbproc):
    pass

def dblib_add_connection(ctx, tds):
    ctx.connection_list.append(tds)

# \internal
# \ingroup dblib_internal
# \brief Sanity checks for column-oriented functions.  
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param pcolinfo address of pointer to a TDSCOLUMN structure.
# \remarks Makes sure dbproc and the requested column are valid.  
#       Calls dbperror() if not.  
# \returns appropriate error or SUCCEED
#
def dbcolptr(dbproc, column):
    if not dbproc:
        dbperror(dbproc, SYBENULL, 0)
        return None
    if IS_TDSDEAD(dbproc.tds_socket):
        dbperror(dbproc, SYBEDDNE, 0)
        return None
    if not dbproc.tds_socket.res_info:
        return None
    if column < 1 or column > len(dbproc.tds_socket.res_info.columns):
        dbperror(dbproc, SYBECNOR, 0)
        return None
    return dbproc.tds_socket.res_info.columns[column - 1]

def dbdata(dbproc, col):
    colinfo = dbproc.res_info.columns[col - 1]
    if colinfo.column_cur_size < 0:
        return None
    if is_blob_col(colinfo):
        raise Exception('not implemented')
        #BYTE *res = (BYTE *) ((TDSBLOB *) colinfo->column_data)->textvalue;
        #if (!res)
        #    return (BYTE *) empty;
        #return res;
    else:
        return colinfo.column_data

#
# \ingroup dblib_core
# \brief Get the datatype of a regular result set column. 
#
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param column Nth in the result set, starting from 1.
# \returns \c SYB* datetype token value, or zero if \a column out of range
# \sa dbcollen(), dbcolname(), dbdata(), dbdatlen(), dbnumcols(), dbprtype(), dbvarylen().
#
def dbcoltype(dbproc, column):
    logger.debug("dbcoltype(%d)" % column)
    #CHECK_PARAMETER(dbproc, SYBENULL, 0)

    colinfo = dbcolptr(dbproc, column)
    if not colinfo:
            return -1

    if colinfo.column_type == SYBVARCHAR:
        return SYBCHAR
    elif colinfo.column_type == SYBVARBINARY:
        return SYBBINARY
    #return tds_get_conversion_type(colinfo.column_type, colinfo.column_size)
    return colinfo.column_type

#
# \ingroup dblib_core
# \brief   Get size of current row's data in a regular result column.  
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param column Nth in the result set, starting from 1.
# \return size of the data, in bytes.
# \sa dbcollen(), dbcolname(), dbcoltype(), dbdata(), dbnumcols().
#
def dbdatlen(dbproc, column):
    logger.debug("dbdatlen(%d)", column)
    CHECK_PARAMETER(dbproc, SYBENULL, -1)

    colinfo = dbcolptr(dbproc, column)
    if not colinfo:
        return -1

    size = 0 if colinfo.column_cur_size < 0 else colinfo.column_cur_size

    logger.debug("dbdatlen() type = %d, len= %d", colinfo.column_type, size)

    return size

def dbnextrow(dbproc):
    logger.debug("dbnextrow()")
    tds = dbproc.tds_socket
    resinfo = tds.res_info
    if not resinfo or dbproc.dbresults_state != _DB_RES_RESULTSET_ROWS:
            # no result set or result set empty (no rows)
        logger.debug("leaving dbnextrow() returning %d (NO_MORE_ROWS)", NO_MORE_ROWS)
        dbproc.row_type = NO_MORE_ROWS
        return NO_MORE_ROWS

    #
    # Try to get the dbproc->row_buf.current item from the buffered rows, if any.  
    # Else read from the stream, unless the buffer is exhausted.  
    # If no rows are read, DBROWTYPE() will report NO_MORE_ROWS. 
    #/
    dbproc.row_type = NO_MORE_ROWS
    computeid = REG_ROW;
    idx = buffer_current_index(dbproc)
    if -1 != idx:
        #
        # Cool, the item we want is already there
        #
        result = dbproc.row_type = REG_ROW
        res_type = TDS_ROW_RESULT
    elif buffer_is_full(dbproc.row_buf):
        result = BUF_FULL
        res_type = TDS_ROWFMT_RESULT
    else:
        pivot = dbrows_pivoted(dbproc)
        if pivot:
            logger.debug("returning pivoted row")
            return dbnextrow_pivoted(dbproc, pivot)
        else:
            mask = TDS_STOPAT_ROWFMT|TDS_RETURN_DONE|TDS_RETURN_ROW|TDS_RETURN_COMPUTE
            buffer_save_row(dbproc)

            # Get the row from the TDS stream.
            rc, res_type, _ = tds_process_tokens(tds, mask)
            if rc == TDS_SUCCESS:
                if res_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                    if res_type == TDS_COMPUTE_RESULT:
                        computeid = tds.current_results.computeid
                    # Add the row to the row buffer, whose capacity is always at least 1
                    resinfo = tds.current_results
                    idx = buffer_add_row(dbproc, resinfo)
                    assert idx != -1
                    result = dbproc.row_type = REG_ROW if res_type == TDS_ROW_RESULT else computeid
                    if False:
                        _, res_type, _ = tds_process_tokens(tds, TDS_TOKEN_TRAILING)
            elif rc == TDS_NO_MORE_RESULTS:
                dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                result = NO_MORE_ROWS
            else:
                logger.debug("unexpected: leaving dbnextrow() returning FAIL")
                return FAIL

    if res_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
        #
        # Transfer the data from the row buffer to the bound variables.
        #
        buffer_transfer_bound_data(dbproc.row_buf, res_type, computeid, dbproc, idx)

    if res_type == TDS_COMPUTE_RESULT:
        logger.debug("leaving dbnextrow() returning compute_id %d\n", result)
    else:
        logger.debug("leaving dbnextrow() returning %s\n", prdbretcode(result))
    return result

# \internal
# \ingroup dblib_internal
# \remarks member msgno Vendor-defined message number
# \remarks member severity Is passed to the error handler 
# \remarks member msgtext Text of message
#
class _dblib_error_message:
    def __init__(self, msgno, severity, msgtext):
        self.msgno = msgno
        self.severity = severity
        self.msgtext = msgtext
DBLIB_ERROR_MESSAGE = _dblib_error_message

#/**  \internal
# * \ingroup dblib_internal
# * \brief Call client-installed error handler
# * 
# * \param dbproc contains all information needed by db-lib to manage communications with the server.
# * \param msgno        identifies the error message to be passed to the client's handler.
# * \param errnum identifies the OS error (errno), if any.  Use 0 if not applicable.  
# * \returns the handler's return code, subject to correction and adjustment for vendor style:
# *     - INT_CANCEL    The db-lib function that encountered the error will return FAIL.  
# *     - INT_TIMEOUT   The db-lib function will cancel the operation and return FAIL.  \a dbproc remains useable.  
# *     - INT_CONTINUE  The db-lib function will retry the operation.  
# * \remarks 
# *     The client-installed handler may also return INT_EXIT.  If Sybase semantics are used, this function notifies
# *     the user and calls exit(3).  If Microsoft semantics are used, this function returns INT_CANCEL.  
# *
# *     If the client-installed handler returns something other than these four INT_* values, or returns timeout-related
# *     value for anything but SYBETIME, it's treated here as INT_EXIT (see above).  
# *
# * Instead of sprinkling error text all over db-lib, we consolidate it here, 
# * where it can be translated (one day), and where it can be mapped to the TDS error number.  
# * The libraries don't use consistent error numbers or messages, so when libtds has to emit 
# * an error message, it can't include the text.  It can pass its error number to a client-library
# * function, which will interpret it, add the text, call the application's installed handler
# * (if any) and return the handler's return code back to the caller.  
# * 
# * The call stack may look something like this:
# *
# * -#  application
# * -#          db-lib function (encounters error)
# * -#          dbperror
# * -#  error handler (installed by application)
# *
# * The error handling in this case is unambiguous: the caller invokes this function, the client's handler returns its 
# * instruction, which the caller receives.  Quite often the caller will get INT_CANCEL, in which case it should put its 
# * house in order and return FAIL.  
# *
# * The call stack may otherwise look something like this:
# *                     
# * -#  application
# * -#          db-lib function
# * -#                  libtds function (encounters error)
# * -#          _dblib_handle_err_message
# * -#          dbperror
# * -#  error handler (installed by application)
# *
# * Because different client libraries specify their handler semantics differently, 
# * and because libtds doesn't know which client library is in charge of any given connection, it cannot interpret the 
# * raw return code from a db-lib error handler.  For these reasons, 
# * libtds calls _dblib_handle_err_message, which translates between libtds and db-lib semantics.  
# * \sa dberrhandle(), _dblib_handle_err_message().
# */
def dbperror (dbproc, msgno, errnum, *args):
    int_exit_text = "FreeTDS: db-lib: exiting because client error handler returned %s for msgno %d\n"
    int_invalid_text = "%s (%d) received from client-installed error handler for nontimeout for error %d."\
                                            "  Treating as INT_EXIT\n"
    default_message = DBLIB_ERROR_MESSAGE( 0, EXCONSISTENCY, "unrecognized msgno" )
    constructed_message = DBLIB_ERROR_MESSAGE( 0, EXCONSISTENCY, None)
    msg = default_message
    raise Exception('not implemented')

#
# \ingroup dblib_core
# \brief Set up query results.  
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED Some results are available.
# \retval FAIL query was not processed successfully by the server
# \retval NO_MORE_RESULTS query produced no results. 
#
# \remarks Call dbresults() after calling dbsqlexec() or dbsqlok(), or dbrpcsend() returns SUCCEED.  Unless
#       one of them fails, dbresults will return either SUCCEED or NO_MORE_RESULTS.  
#
#       The meaning of \em results is very specific and not very intuitive.  Results are created by either
#       - a SELECT statement
#       - a stored procedure
#
#       When dbresults returns SUCCEED, therefore, it indicates the server processed the query successfully and 
#       that one or more of these is present:
#       - metadata -- dbnumcols() returns 1 or more
#       - data -- dbnextrow() returns SUCCEED
#       - return status -- dbhasretstat() returns TRUE
#       - output parameters -- dbnumrets() returns 1 or more
#
#       If none of the above are present, dbresults() returns NO_MORE_RESULTS.  
#       
#       SUCCEED does not imply that DBROWS() will return TRUE or even that dbnumcols() will return nonzero.  
#       A general algorithm for reading results will call dbresults() until it return NO_MORE_RESULTS (or FAIL).  
#       An application should check for all the above kinds of results within the dbresults() loop.  
# 
# \sa dbsqlexec(), dbsqlok(), dbrpcsend(), dbcancel(), DBROWS(), dbnextrow(), dbnumcols(), dbhasretstat(), dbretstatus(), dbnumrets()
#
def dbresults(dbproc):
    erc = _dbresults(dbproc);
    logger.debug("dbresults returning %d (%s)", erc, prdbretcode(erc))
    return erc;

def _dbresults(dbproc):
    result_type = 0

    tds = dbproc.tds_socket

    logger.debug("dbresults: dbresults_state is %d (%s)\n", 
                                    dbproc.dbresults_state, prdbresults_state(dbproc.dbresults_state))
    if dbproc.dbresults_state == _DB_RES_SUCCEED:
        dbproc.dbresults_state = _DB_RES_NEXT_RESULT
        return SUCCEED
    elif dbproc.dbresults_state == _DB_RES_RESULTSET_ROWS:
        dbperror(dbproc, SYBERPND, 0) # dbresults called while rows outstanding....
        return FAIL;
    elif dbproc.dbresults_state == _DB_RES_NO_MORE_RESULTS:
        return NO_MORE_RESULTS;

    while True:
        retcode, result_type, done_flags = tds_process_tokens(tds, TDS_TOKEN_RESULTS)

        logger.debug("dbresults() tds_process_tokens returned %d (%s),\n\t\t\tresult_type %s\n", 
                                        retcode, prretcode(retcode), prresult_type(result_type))

        if retcode == TDS_SUCCESS:
            if result_type == TDS_ROWFMT_RESULT:
                #buffer_free(&dbproc->row_buf);
                #buffer_alloc(dbproc);
                dbproc.dbresults_state = _DB_RES_RESULTSET_EMPTY

            elif result_type == TDS_COMPUTEFMT_RESULT:
                pass

            elif result_type in (TDS_ROW_RESULT, TDS_COMPUTE_RESULT):
                dbproc.dbresults_state = _DB_RES_RESULTSET_ROWS
                return SUCCEED

            elif result_type in (TDS_DONE_RESULT, TDS_DONEPROC_RESULT):
                logger.debug("dbresults(): dbresults_state is %d (%s)\n", 
                                dbproc.dbresults_state, prdbresults_state(dbproc.dbresults_state))

                # A done token signifies the end of a logical command.
                # There are three possibilities:
                # 1. Simple command with no result set, i.e. update, delete, insert
                # 2. Command with result set but no rows
                # 3. Command with result set and rows
                #
                if dbproc.dbresults_state in (_DB_RES_INIT, _DB_RES_NEXT_RESULT):
                    dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                    if done_flags & TDS_DONE_ERROR:
                        return FAIL

                elif dbproc.dbresults_state in (_DB_RES_RESULTSET_EMPTY, _DB_RES_RESULTSET_ROWS):
                    dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                    return SUCCEED
                else:
                    assert False

            elif result_type == TDS_DONEINPROC_RESULT:
                    #
                    # Return SUCCEED on a command within a stored procedure
                    # only if the command returned a result set. 
                    #
                    if dbproc.dbresults_state in (_DB_RES_INIT, _DB_RES_NEXT_RESULT):
                        dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                    elif dbproc.dbresults_state in (_DB_RES_RESULTSET_EMPTY, _DB_RES_RESULTSET_ROWS):
                        dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                        return SUCCEED;
                    elif dbproc.dbresults_state in (_DB_RES_NO_MORE_RESULTS, _DB_RES_SUCCEED):
                        pass

            elif result_type in (TDS_STATUS_RESULT, TDS_MSG_RESULT, TDS_DESCRIBE_RESULT, TDS_PARAM_RESULT):
                pass
            else:
                pass
        elif ret_code == TDS_NO_MORE_RESULTS:
            dbproc.dbresults_state = _DB_RES_NO_MORE_RESULTS
            return NO_MORE_RESULTS
        else:
            assert TDS_FAILED(retcode)
            dbproc.dbresults_state = _DB_RES_INIT
            return FAIL

#
# \ingroup dblib_core
# \brief \c Append SQL to the command buffer.  
#
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \param cmdstring SQL to append to the command buffer.  
# \retval SUCCEED success.
# \retval FAIL insufficient memory.  
# \remarks set command state to \c  DBCMDPEND unless the command state is DBCMDSENT, in which case 
# it frees the command buffer.  This latter may or may not be the Right Thing to do.  
# \sa dbfcmd(), dbfreebuf(), dbgetchar(), dbopen(), dbstrcpy(), dbstrlen().
#
def dbcmd(dbproc, cmdstring):
    logger.debug("dbcmd(%s)", cmdstring)
    #CHECK_NULP(cmdstring, "dbcmd", 2, FAIL)

    dbproc.avail_flag = False

    #logger.debug("dbcmd() bufsz = %d", dbproc.dbbufsz)

    if dbproc.command_state == DBCMDSENT:
        if not dbproc.noautofree:
            dbfreebuf(dbproc)

    dbproc.dbbuf = cmdstring
    dbproc.command_state = DBCMDPEND

#
# \ingroup dblib_core
# \brief send the SQL command to the server and wait for an answer.  
# 
# Please be patient.  This function waits for the server to respond.   \c dbsqlexec is equivalent
# to dbsqlsend() followed by dbsqlok(). 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED query was processed without errors.
# \retval FAIL was returned by dbsqlsend() or dbsqlok().
# \sa dbcmd(), dbfcmd(), dbnextrow(), dbresults(), dbretstatus(), dbsettime(), dbsqlok(), dbsqlsend()
#
def dbsqlexec(dbproc):
    logger.debug("dbsqlexec()")
    dbsqlsend(dbproc)
    rc = dbsqlok(dbproc)
    return rc

#
# \ingroup dblib_core
# \brief Transmit the command buffer to the server.  \em Non-blocking, does not wait for a response.
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED SQL sent.
# \retval FAIL protocol problem, unless dbsqlsend() when it's not supposed to be (in which case a db-lib error
# message will be emitted).  
# \sa dbcmd(), dbfcmd(), DBIORDESC(), DBIOWDESC(), dbnextrow(), dbpoll(), dbresults(), dbsettime(), dbsqlexec(), dbsqlok().  
#
def dbsqlsend(dbproc):
    logger.debug("dbsqlsend()")

    tds = dbproc.tds_socket

    if tds.state == TDS_PENDING:
        raise Exception('not checked')
        rc, result_type, _ = tds_process_tokens(tds, result_type, TDS_TOKEN_TRAILING)
        if rc != TDS_NO_MORE_RESULTS:
            dbperror(dbproc, SYBERPND, 0)
            dbproc.command_state = DBCMDSENT
            return FAIL

    if dbproc.dboptcmd:
        raise Exception('not converted')
        #if ((cmdstr = dbstring_get(dbproc.dboptcmd)) == NULL) {
        #    dbperror(dbproc, SYBEASEC, 0); /* Attempt to send an empty command buffer to the server */
        #    return FAIL;
        #}
        #rc = tds_submit_query(dbproc->tds_socket, cmdstr);
        #free(cmdstr);
        #dbstring_free(&(dbproc->dboptcmd));
        #if (TDS_FAILED(rc)) {
        #    return FAIL;
        #}
        #dbproc->avail_flag = FALSE;
        #dbproc->envchange_rcv = 0;
        #dbproc->dbresults_state = _DB_RES_INIT;
        #while ((rc = tds_process_tokens(tds, &result_type, NULL, TDS_TOKEN_RESULTS))
        #        == TDS_SUCCESS);
        #if (rc != TDS_NO_MORE_RESULTS) {
        #    return FAIL;
        #}
    dbproc.more_results = True

    #if (dbproc->ftos != NULL) {
    #        fprintf(dbproc->ftos, "%s\n", dbproc->dbbuf);
    #        fprintf(dbproc->ftos, "go /* %s */\n", _dbprdate(timestr));
    #        fflush(dbproc->ftos);
    #}

    tds_submit_query(dbproc.tds_socket, dbproc.dbbuf)
    dbproc.avail_flag = False
    dbproc.envchange_rcv = 0
    dbproc.dbresults_state = _DB_RES_INIT
    dbproc.command_state = DBCMDSENT

class _DbProcRowBuf:
    pass

class _DbProcess:
    def __init__(self):
        self.row_buf = _DbProcRowBuf()
        self.text_sent = False

# \internal
# \ingroup dblib_internal
# \brief Form a connection with the server.
#   
# Called by the \c dbopen() macro, normally.  If FreeTDS was configured with \c --enable-msdblib, this
# function is called by (exported) \c dbopen() function.  \c tdsdbopen is so-named to avoid
# namespace conflicts with other database libraries that use the same function name.  
# \param login \c LOGINREC* carrying the account information.
# \param server name of the dataserver to connect to.  
# \return valid pointer on successful login.  
# \retval NULL insufficient memory, unable to connect for any reason.
# \sa dbopen()
# \todo use \c asprintf() to avoid buffer overflow.
# \todo separate error messages for \em no-such-server and \em no-such-user. 
#
def tdsdbopen(login, server, msdblib):
    dbproc = None

    logger.debug("dbopen(%s, [%s])\n", server if server else "0x0", "microsoft" if msdblib else "sybase")

    #
    # Sybase supports the DSQUERY environment variable and falls back to "SYBASE" if server is NULL. 
    # Microsoft uses a NULL or "" server to indicate a local server.  
    # FIXME: support local server for win32.
    #
    if not server and not msdblib:
        raise Exception('not converted')
        #if (server = getenv("TDSQUERY")) == NULL)
        #        if ((server = getenv("DSQUERY")) == NULL)
        #                server = "SYBASE";
        #tdsdump_log(TDS_DBG_FUNC, "servername set to %s", server);

    dbproc = _DbProcess()
    dbproc.msdblib = msdblib

    #dbproc.dbopts = init_dboptions()
    #if dbproc.dbopts is None:
    #    raise Exception('fail')

    dbproc.dboptcmd = None
    dbproc.avail_flag = True
    dbproc.command_state = DBCMDNONE
    tds_set_server(login.tds_login, server)
    dbproc.tds_socket = tds_alloc_socket(dblib_get_tds_ctx(), 512)

    tds_set_parent(dbproc.tds_socket, dbproc)

    dbproc.tds_socket.env_chg_func = db_env_chg
    dbproc.envchange_rcv = 0

    dbproc.dbcurdb = ''
    dbproc.servcharset = '\0'

    connection = tds_read_config_info(dbproc.tds_socket, login.tds_login, g_dblib_ctx.tds_ctx.locale)
    if not connection:
        dbclose(dbproc)
        return None
    connection.option_flag2 &= ~0x02 # we're not an ODBC driver
    tds_fix_login(connection) # initialize from Environment variables

    dbproc.chkintr = None
    dbproc.hndlintr = None

    TDS_MUTEX_LOCK(dblib_mutex)
    try:

        # override connection timeout if dbsetlogintime() was called
        if g_dblib_ctx.login_timeout > 0:
            connection.connect_timeout = g_dblib_ctx.login_timeout

        # override query timeout if dbsettime() was called
        if g_dblib_ctx.query_timeout > 0:
            connection.query_timeout = g_dblib_ctx.query_timeout
    finally:
        TDS_MUTEX_UNLOCK(dblib_mutex)

    if TDS_FAILED(tds_connect_and_login(dbproc.tds_socket, connection)):
        tds_free_login(connection)
        dbclose(dbproc)
        return NULL
    tds_free_login(connection)

    dbproc.dbbuf = None
    dbproc.dbbufsz = 0

    TDS_MUTEX_LOCK(dblib_mutex)
    dblib_add_connection(g_dblib_ctx, dbproc.tds_socket)
    TDS_MUTEX_UNLOCK(dblib_mutex)

    # set the DBBUFFER capacity to nil
    buffer_set_capacity(dbproc, 0);

    #TDS_MUTEX_LOCK(dblib_mutex)
    #if g_dblib_ctx.recftos_filename != NULL) {
    #        char *temp_filename = NULL;
    #        const int len = asprintf(&temp_filename, "%s.%d", 
    #                                    g_dblib_ctx.recftos_filename, g_dblib_ctx.recftos_filenum);
    #        if (len >= 0) {
    #                dbproc->ftos = fopen(temp_filename, "w");
    #                if (dbproc->ftos != NULL) {
    #                        fprintf(dbproc->ftos, "/* dbopen() at %s */\n", _dbprdate(temp_filename));
    #                        fflush(dbproc->ftos);
    #                        g_dblib_ctx.recftos_filenum++;
    #                }
    #                free(temp_filename);
    #        }
    #}
    #
    #memcpy(dbproc->nullreps, default_null_representations, sizeof(default_null_representations));

    #TDS_MUTEX_UNLOCK(&dblib_mutex);

    return dbproc

def dbopen(login, server):
    return tdsdbopen(login, server, 1)

class _LoginRec:
    pass

#
# \ingroup dblib_core
# \brief Allocate a \c LOGINREC structure.  
#
# \remarks A \c LOGINREC structure is passed to \c dbopen() to create a connection to the database. 
#       Does not communicate to the server; interacts strictly with library.  
# \retval NULL the \c LOGINREC cannot be allocated.
# \retval LOGINREC* to valid memory, otherwise.  
#
def dblogin():
    logger.debug("dblogin(void)")
    loginrec = _LoginRec()
    loginrec.tds_login = tds_alloc_login(1)
    # set default values for loginrec
    loginrec.tds_login.library = "DB-Library"
    return loginrec

#
# \ingroup dblib_core
# \brief Set maximum seconds db-lib waits for a server response to a login attempt.  
# 
# \param seconds New limit for application.  
# \retval SUCCEED Always.  
# \sa dberrhandle(), dbsettime()
#
def dbsetlogintime(seconds):
    logger.debug("dbsetlogintime(%d)", seconds)

    TDS_MUTEX_LOCK(dblib_mutex)
    g_dblib_ctx.login_timeout = seconds
    TDS_MUTEX_UNLOCK(dblib_mutex)

#* \internal
# \ingroup dblib_internal
# \brief default error handler for db-lib (handles library-generated errors)
# 
# The default error handler doesn't print anything.  If you want to see your messages printed, 
# install an error handler.  If you think that should be an optional compile- or run-time default, 
# submit a patch.  It could be done.  
# 
# \sa DBDEAD(), dberrhandle().
#/
# Thus saith Sybase:
#     "If the user does not supply an error handler (or passes a NULL pointer to 
#       dberrhandle), DB-Library will exhibit its default error-handling 
#       behavior: It will abort the program if the error has made the affected 
#       DBPROCESS unusable (the user can call DBDEAD to determine whether 
#       or not a DBPROCESS has become unusable). If the error has not made the 
#       DBPROCESS unusable, DB-Library will simply return an error code to its caller." 
#
# It is not the error handler, however, that aborts anything.  It is db-lib, cf. dbperror().  
#/ 
def default_err_handler(dbproc, severity, dberr, oserr, dberrstr, oserrstr):
    logger.debug("default_err_handler %d, %d, %d, %s, %s", severity, dberr, oserr, dberrstr, oserrstr)

    if DBDEAD(dbproc) and not dbproc or not dbproc.msdblib:
        return INT_EXIT

    if not dbproc or not dbproc.msdblib: # i.e. Sybase behavior
        if dberr == SYBETIME:
            return INT_EXIT
        else:
            pass
    return INT_CANCEL

_dblib_msg_handler = None
_dblib_err_handler = default_err_handler
class _DbLibCtx:
    def __init__(self):
        self.ref_count = 0
        self.tds_ctx = None
        self.tds_ctx_ref_count = 0
g_dblib_ctx = _DbLibCtx()

#
# \ingroup dblib_core
# \brief Initialize db-lib.  
#
# \remarks Call this function before trying to use db-lib in any way.  
# Allocates various internal structures and reads \c locales.conf (if any) to determine the default
# date format.  
# \retval SUCCEED normal.  
# \retval FAIL cannot allocate an array of \c TDS_MAX_CONN \c TDSSOCKET pointers.  
#
def dbinit():
    global _dblib_err_handler
    _dblib_err_handler = default_err_handler

    TDS_MUTEX_LOCK(dblib_mutex)

    logger.debug("dbinit(void)")

    is_already_initialized = g_dblib_ctx.ref_count != 0
    g_dblib_ctx.ref_count += 1

    if is_already_initialized:
        TDS_MUTEX_UNLOCK(dblib_mutex)
        return
    # DBLIBCONTEXT stores a list of current connections so they may be closed with dbexit()
    g_dblib_ctx.connection_list = []
    g_dblib_ctx.connection_list_size = 1000
    g_dblib_ctx.connection_list_size_represented = 1000


    g_dblib_ctx.login_timeout = -1
    g_dblib_ctx.query_timeout = -1

    TDS_MUTEX_UNLOCK(dblib_mutex)

    dblib_get_tds_ctx()

#/**
# * \ingroup dblib_core
# * \brief Set an error handler, for messages from db-lib.
# * 
# * \param handler pointer to callback function that will handle errors.
# *        Pass NULL to restore the default handler.  
# * \return address of prior handler, or NULL if none was previously installed. 
# * \sa DBDEAD(), dbmsghandle().
# */
def dberrhandle(handler):
    old_handler = _dblib_err_handler
    global _dblib_err_handler
    _dblib_err_handler = handler if handler else default_err_handler
    return None if old_handler is default_err_handler else old_handler

#/**
# * \ingroup dblib_core
# * \brief Set a message handler, for messages from the server.
# * 
# * \param handler address of the function that will process the messages.
# * \sa DBDEAD(), dberrhandle().
# */
def dbmsghandle(handler):
    global _dblib_msg_handler
    retFun = _dblib_msg_handler
    _dblib_msg_handler = handler
    return retFun

def dblib_get_tds_ctx():
    #logger(TDS_DBG_FUNC, "dblib_get_tds_ctx(void)\n");

    TDS_MUTEX_LOCK(dblib_mutex)
    g_dblib_ctx.tds_ctx_ref_count += 1
    if g_dblib_ctx.tds_ctx is None:
        g_dblib_ctx.tds_ctx = tds_alloc_context(g_dblib_ctx)

        #
        # Set the functions in the TDS layer to point to the correct handler functions
        #
        g_dblib_ctx.tds_ctx.msg_handler = _dblib_handle_info_message
        g_dblib_ctx.tds_ctx.err_handler = _dblib_handle_err_message
        g_dblib_ctx.tds_ctx.int_handler = _dblib_check_and_handle_interrupt

        if g_dblib_ctx.tds_ctx.locale and not g_dblib_ctx.tds_ctx.locale.date_fmt:
            # set default in case there's no locale file
            date_format = "%b %e %Y %I:%M:%S:%z%p"
            g_dblib_ctx.tds_ctx.locale.date_fmt = date_format
    TDS_MUTEX_UNLOCK(dblib_mutex)
    return g_dblib_ctx.tds_ctx

def db_env_chg(tds, type, oldval, newval):
    assert oldval is not None and newval is not None
    if oldval == '\x01':
        oldval = "(0x1)"

    logger.debug("db_env_chg(%d, %s, %s)", type, oldval, newval)

    if not tds or not tds_get_parent(tds):
        return
    dbproc = tds_get_parent(tds)

    dbproc.envchange_rcv |= (1 << (type - 1))
    if type == TDS_ENV_DATABASE:
        dbproc.dbcurdb = newval
    elif type == TDS_ENV_CHARSET:
        dbproc.servcharset = newval

def _dblib_handle_info_message(tds_ctx, tds, msg):
    raise Exception('not implemented')

def _dblib_handle_err_message(tds_ctx, tds, msg):
    raise Exception('not implemented')

def _dblib_check_and_handle_interrupt(vdbproc):
    raise Exception('not implemented')

#*
# \ingroup dblib_core
# \brief Wait for results of a query from the server.  
# 
# \param dbproc contains all information needed by db-lib to manage communications with the server.
# \retval SUCCEED everything worked, fetch results with \c dbnextresults().
# \retval FAIL SQL syntax error, typically.  
# \sa dbcmd(), dbfcmd(), DBIORDESC(), DBIOWDESC(), dbmoretext(), dbnextrow(),
#     dbpoll(), DBRBUF(), dbresults(), dbretstatus(), dbrpcsend(), dbsettime(), dbsqlexec(),
#     dbsqlsend(), dbwritetext().
#/
def dbsqlok(dbproc):
    return_code = SUCCEED
    logger.debug("dbsqlok()")
    #CHECK_CONN(FAIL);

    tds = dbproc.tds_socket
    #
    # dbsqlok has been called after dbmoretext()
    # This is the trigger to send the text data.
    #
    if dbproc.text_sent:
        tds_flush_packet(tds)
        dbproc.text_sent = 0

    #
    # See what the next packet from the server is.
    # We want to skip any messages which are not processable. 
    # We're looking for a result token or a done token.
    #
    while True:
        done_flags = 0

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
                return SUCCEED;

        elif tds_code == TDS_SUCCESS:
            if result_type == TDS_ROWFMT_RESULT:
                buffer_free(dbproc.row_buf)
                buffer_alloc(dbproc)
            elif result_type == TDS_COMPUTEFMT_RESULT:
                dbproc.dbresults_state = _DB_RES_RESULTSET_EMPTY;
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
                            dbproc.dbresults_state = _DB_RES_NEXT_RESULT
                        else:
                            dbproc.dbresults_state = _DB_RES_NO_MORE_RESULTS

                    else:
                        logger.debug("dbsqlok() end status was success")
                        dbproc.dbresults_state = _DB_RES_SUCCEED
                    return return_code
                else:
                    retcode = FAIL if done_flags & TDS_DONE_ERROR else SUCCEED;
                    dbproc.dbresults_state = _DB_RES_NEXT_RESULT if done_flags & TDS_DONE_MORE_RESULTS else _DB_RES_NO_MORE_RESULTS
                    logger.debug("dbsqlok: returning %s with %s (%#x)", 
                                    prdbretcode(retcode), prdbresults_state(dbproc.dbresults_state), done_flags)
                    if retcode == SUCCEED and (done_flags & TDS_DONE_MORE_RESULTS):
                        continue
                    return retcode
            else:
                logger.debug('logic error: tds_process_tokens result_type %d', result_type);
        else:
            assert TDS_FAILED(tds_code)
            return FAIL

    return SUCCEED

def dbnumcols(dbproc):
    logger.debug("dbnumcols()")
    #CHECK_PARAMETER(dbproc, SYBENULL, 0)

    if dbproc and dbproc.tds_socket and dbproc.tds_socket.res_info:
        return dbproc.tds_socket.res_info.num_cols
    return 0

#/**
# * \ingroup dblib_core
# * \brief Get count of rows processed
# *
# *
# * \param dbproc contains all information needed by db-lib to manage communications with the server.
# * \returns
# * 	- for insert/update/delete, count of rows affected.
# * 	- for select, count of rows returned, after all rows have been fetched.
# * \sa DBCOUNT(), dbnextrow(), dbresults().
# */
def dbcount(dbproc):
    logger.debug("dbcount()")
    #CHECK_PARAMETER(dbproc, SYBENULL, -1);

    if not dbproc or not dbproc.tds_socket or dbproc.tds_socket.rows_affected == TDS_NO_COUNT:
        return -1
    return dbproc.tds_socket.rows_affected

#/**
# * \ingroup dblib_core
# * \brief Return name of a regular result column.
# * 
# * \param dbproc contains all information needed by db-lib to manage communications with the server.
# * \param column Nth in the result set, starting with 1.  
# * \return pointer to ASCII null-terminated string, the name of the column. 
# * \retval NULL \a column is not in range.
# * \sa dbcollen(), dbcoltype(), dbdata(), dbdatlen(), dbnumcols().
# * \bug Relies on ASCII column names, post iconv conversion.  
# *      Will not work as described for UTF-8 or UCS-2 clients.  
# *      But maybe it shouldn't.  
# */
def dbcolname(dbproc,  column):
    logger.debug("dbcolname(%d)", column)
    #CHECK_PARAMETER(dbproc, SYBENULL, 0);

    colinfo = dbcolptr(dbproc, column)
    if not colinfo:
        return None
    return colinfo.column_name

def prdbresults_state(retcode):
    if retcode == _DB_RES_INIT:                 return "_DB_RES_INIT"
    elif retcode == _DB_RES_RESULTSET_EMPTY:    return "_DB_RES_RESULTSET_EMPTY"
    elif retcode == _DB_RES_RESULTSET_ROWS:     return "_DB_RES_RESULTSET_ROWS"
    elif retcode == _DB_RES_NEXT_RESULT:        return "_DB_RES_NEXT_RESULT"
    elif retcode == _DB_RES_NO_MORE_RESULTS:    return "_DB_RES_NO_MORE_RESULTS"
    elif retcode == _DB_RES_SUCCEED:            return "_DB_RES_SUCCEED"
    else: return "oops: %d ??" % retcode

def prdbretcode(retcode):
    if retcode == REG_ROW:            return "REG_ROW/MORE_ROWS"
    elif retcode == NO_MORE_ROWS:       return "NO_MORE_ROWS"
    elif retcode == BUF_FULL:           return "BUF_FULL"
    elif retcode == NO_MORE_RESULTS:    return "NO_MORE_RESULTS"
    elif retcode == SUCCEED:            return "SUCCEED"
    elif retcode == FAIL:               return "FAIL"
    else: return "oops: %u ??" % retcode

def prretcode(retcode):
    if retcode == TDS_SUCCESS:                  return "TDS_SUCCESS"
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
