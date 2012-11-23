import logging
import traceback
from read import *
from tdsproto import *
from iconv import *
from mem import *
from tds_checks import *
from data import *

logger = logging.getLogger(__name__)

token_names = {
0x20: "TDS5_PARAMFMT2",
0x22: "ORDERBY2",
0x61: "ROWFMT2",
0x71: "LOGOUT",
0x79: "RETURNSTATUS",
0x7C: "PROCID",
0x81: "TDS7_RESULT",
0x83: "TDS_CURINFO",
0x88: "TDS7_COMPUTE_RESULT",
0xA0: "COLNAME",
0xA1: "COLFMT",
0xA3: "DYNAMIC2",
0xA4: "TABNAME",
0xA5: "COLINFO",
0xA7: "COMPUTE_NAMES",
0xA8: "COMPUTE_RESULT",
0xA9: "ORDERBY",
0xAA: "ERROR",
0xAB: "INFO",
0xAC: "PARAM",
0xAD: "LOGINACK",
0xAE: "CONTROL",
0xD1: "ROW",
0xD3: "CMP_ROW",
0xD7: "TDS5_PARAMS",
0xE2: "CAPABILITY",
0xE3: "ENVCHANGE",
0xE5: "EED",
0xE6: "DBRPC",
0xE7: "TDS5_DYNAMIC",
0xEC: "TDS5_PARAMFMT",
0xED: "AUTH",
0xEE: "RESULT",
0xFD: "DONE",
0xFE: "DONEPROC",
0xFF: "DONEINPROC",
}

def tds_token_name(marker):
    return token_names.get(marker, '')

def tds_process_default_tokens(tds, marker):
    logger.debug('tds_process_default_tokens() marker is {0:x}({1})'.format(marker, tds_token_name(marker)))
    if tds.is_dead():
        logger.debug('leaving tds_process_login_tokens() connection dead')
        tds_close_socket(tds)
        raise Exception('TDS_FAIL')
    if marker == TDS_AUTH_TOKEN:
        return tds_process_auth(tds)
    elif marker == TDS_ENVCHANGE_TOKEN:
        return tds_process_env_chg(tds)
    elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
        rc, _ = tds_process_end(tds, marker)
        return rc
    elif marker in (TDS_ERROR_TOKEN, TDS_INFO_TOKEN, TDS_EED_TOKEN):
        tds_process_msg(tds, marker)
    elif marker == TDS_CAPABILITY_TOKEN:
        # TODO split two part of capability and use it
        tok_size = tds_get_smallint(tds)
        # vicm
        #
        # Sybase 11.0 servers return the wrong length in the capability packet, causing use to read
        # past the done packet.
        #
        if not TDS_IS_MSSQL(tds) and tds_conn(tds).product_version < TDS_SYB_VER(12, 0, 0):
            raise Exception('not supported')
            #p = tds_conn(tds).capabilities;
            #pend = tds_conn(tds)->capabilities + TDS_MAX_CAPABILITY;

            #while True:
            #    type = tds_get_byte(tds)
            #    size = tds_get_byte(tds)
            #    if ((p + 2) > pend)
            #        break
            #    *p++ = type;
            #    *p++ = size;
            #    if ((p + size) > pend)
            #        break
            #    if (tds_get_n(tds, p, size) == NULL)
            #        return TDS_FAIL;
            #    if type == 2:
            #        break
        else:
            tds_conn(tds).capabilities = tds_get_n(tds, min(tok_size, TDS_MAX_CAPABILITY))
            # PARAM_TOKEN can be returned inserting text in db, to return new timestamp
    elif marker == TDS_PARAM_TOKEN:
        tds_unget_byte(tds)
        return tds_process_param_result_tokens(tds)
    elif marker == TDS7_RESULT_TOKEN:
        return tds7_process_result(tds)
    elif marker == TDS_OPTIONCMD_TOKEN:
        return tds5_process_optioncmd(tds)
    elif marker == TDS_RESULT_TOKEN:
        return tds_process_result(tds)
    elif marker == TDS_ROWFMT2_TOKEN:
        return tds5_process_result(tds)
    elif marker == TDS_COLNAME_TOKEN:
        return tds_process_col_name(tds)
    elif marker == TDS_COLFMT_TOKEN:
        return tds_process_col_fmt(tds)
    elif marker == TDS_ROW_TOKEN:
        return tds_process_row(tds)
    elif marker == TDS5_PARAMFMT_TOKEN:
        # store discarded parameters in param_info, not in old dynamic
        tds.cur_dyn = None
        return tds_process_dyn_result(tds)
    elif marker == TDS5_PARAMFMT2_TOKEN:
        tds.cur_dyn = None
        return tds5_process_dyn_result2(tds)
    elif marker == TDS5_PARAMS_TOKEN:
        # save params
        return tds_process_params_result_token(tds)
    elif marker == TDS_CURINFO_TOKEN:
        return tds_process_cursor_tokens(tds)
    elif marker in (TDS5_DYNAMIC_TOKEN, TDS_LOGINACK_TOKEN, TDS_ORDERBY_TOKEN, TDS_CONTROL_TOKEN):
        logger.debug("Eating %s token", tds_token_name(marker))
        tds_skip_n(tds, tds_get_smallint(tds))
    elif marker == TDS_TABNAME_TOKEN: # used for FOR BROWSE query
        return tds_process_tabname(tds)
    elif marker == TDS_COLINFO_TOKEN:
        return tds_process_colinfo(tds, None, 0)
    elif marker == TDS_ORDERBY2_TOKEN:
        logger.debug("Eating %s token", tds_token_name(marker))
        tds_skip_n(tds, tds_get_int(tds))
    elif marker == TDS_NBC_ROW_TOKEN:
        return tds_process_nbcrow(tds)
    else:
        tds_close_socket(tds)
        logger.error('Unknown marker: {0}({0:x}) {1}'.format(marker, ''.join(traceback.format_stack())))
        raise Exception('TDSEBTOK')

#
# tds_process_row() processes rows and places them in the row buffer.
#
def tds_process_row(tds):
    CHECK_TDS_EXTRA(tds)

    info = tds.current_results
    if not info:
        raise Exception('TDS_FAIL')

    assert info.num_cols > 0

    info.row_count += 1
    for i, curcol in enumerate(info.columns):
        logger.debug("tds_process_row(): reading column %d" % i)
        curcol.funcs.get_data(tds, curcol)
    return TDS_SUCCESS

# NBC=null bitmap compression row
# http://msdn.microsoft.com/en-us/library/dd304783(v=prot.20).aspx
def tds_process_nbcrow(tds):
    info = tds.current_results
    if not info:
        raise Exception('TDS_FAIL')
    assert info.num_cols > 0
    info.row_count += 1

    # reading bitarray for nulls, 1 represent null values for
    # corresponding fields
    nbc = tds_get_n(tds, (len(info.columns) + 7) / 8)
    for i, curcol in enumerate(info.columns):
        if ord(nbc[i/8]) & (1 << i%8):
            curcol.value = None
        else:
            curcol.funcs.get_data(tds, curcol)
    return TDS_SUCCESS
#
# tds_process_end() processes any of the DONE, DONEPROC, or DONEINPROC
# tokens.
# \param tds        state information for the socket and the TDS protocol
# \param marker     TDS token number
# \param flags_parm filled with bit flags (see TDS_DONE_ constants). 
#        Is NULL nothing is returned
#
def tds_process_end(tds, marker):
    tmp = tds_get_smallint(tds)
    state = tds_get_smallint(tds)
    more_results = tmp & TDS_DONE_MORE_RESULTS != 0
    was_cancelled = tmp & TDS_DONE_CANCELLED != 0
    error = tmp & TDS_DONE_ERROR != 0
    done_count_valid = tmp & TDS_DONE_COUNT != 0
    logger.debug('tds_process_end: more_results = {0}\n'
            '\t\twas_cancelled = {1}\n'
            '\t\terror = {2}\n'
            '\t\tdone_count_valid = {3}'.format(more_results, was_cancelled, error, done_count_valid))
    if tds.res_info:
        tds.res_info.more_results = more_results
        if not tds.current_results:
            tds.current_results = tds.res_info
    rows_affected = tds_get_int8(tds) if IS_TDS72_PLUS(tds) else tds_get_int(tds)
    logger.debug('\t\trows_affected = {0}'.format(rows_affected))
    if was_cancelled or (not more_results and not tds.in_cancel):
        logger.debug('tds_process_end() state set to TDS_IDLE')
        tds.in_cancel = False
        tds_set_state(tds, TDS_IDLE)
    if tds.is_dead():
        raise Exception('TDS_FAIL')
    if done_count_valid:
        tds.rows_affected = rows_affected
    else:
        tds.rows_affected = None
    return (TDS_CANCELLED if was_cancelled else TDS_SUCCESS), tmp

def tds_process_env_chg(tds):
    size = tds_get_smallint(tds)
    type = tds_get_byte(tds)
    if type == TDS_ENV_SQLCOLLATION:
        size = tds_get_byte(tds)
        logger.debug("tds_process_env_chg(): {0} bytes of collation data received".format(size))
        logger.debug("tds.collation was {0}".format(tds.collation));
        if size < 5:
            tds.collation = tds_get_n(tds, size)
        else:
            tds.collation = tds_get_n(tds, 5)
            tds_get_n(tds, size - 5)
            lcid = (ord(tds.collation[0]) + (ord(tds.collation[1]) << 8) + (ord(tds.collation[2]) << 16)) & 0xfffff
            tds7_srv_charset_changed(tds, ord(tds.collation[4]), lcid)
        logger.debug("tds.collation now {0}".format(tds.collation));
        # discard old one
        tds_get_n(tds, tds_get_byte(tds))
    elif type == TDS_ENV_BEGINTRANS:
        size = tds_get_byte(tds)
        tds.tds72_transaction = tds_get_n(tds, 8)
        tds_get_n(tds, tds_get_byte(tds))
    elif type == TDS_ENV_COMMITTRANS or type == TDS_ENV_ROLLBACKTRANS:
        tds.tds72_transaction = None
        tds_get_n(tds, tds_get_byte(tds))
        tds_get_n(tds, tds_get_byte(tds))
    elif type == TDS_ENV_PACKSIZE:
        newval = tds_get_string(tds, tds_get_byte(tds))
        oldval = tds_get_string(tds, tds_get_byte(tds))
        new_block_size = int(newval)
        if new_block_size >= 512:
            logger.info("changing block size from {0} to {1}".format(oldval, new_block_size))
            #
            # Is possible to have a shrink if server limits packet
            # size more than what we specified
            #
            # Reallocate buffer if possible (strange values from server or out of memory) use older buffer */
            tds_realloc_socket(tds, new_block_size)
    elif type == TDS_ENV_DATABASE:
        newval = tds_get_string(tds, tds_get_byte(tds))
        oldval = tds_get_string(tds, tds_get_byte(tds))
        tds.env.database = newval
    elif type == TDS_ENV_LANG:
        newval = tds_get_string(tds, tds_get_byte(tds))
        oldval = tds_get_string(tds, tds_get_byte(tds))
        tds.env.language = newval
    elif type == TDS_ENV_CHARSET:
        newval = tds_get_string(tds, tds_get_byte(tds))
        oldval = tds_get_string(tds, tds_get_byte(tds))
        logger.debug("server indicated charset change to \"{0}\"\n".format(newval))
        tds.env.charset = newval
        tds_srv_charset_changed(tds, newval)
    elif type == TDS_ENV_DB_MIRRORING_PARTNER:
        newval = tds_get_string(tds, tds_get_byte(tds))
        oldval = tds_get_string(tds, tds_get_byte(tds))

    else:
        # discard byte values, not still supported
        # TODO support them
        # discard new one
        tds_get_n(tds, tds_get_byte(tds))
        # discard old one
        tds_get_n(tds, tds_get_byte(tds))


def tds_process_msg(tds, marker):
    size = tds_get_smallint(tds)
    msg = {}
    msg['msgno'] = tds_get_int(tds)
    msg['state'] = tds_get_byte(tds)
    msg['severity'] = tds_get_byte(tds)
    msg['sql_state'] = None
    has_eed = False
    if marker == TDS_EED_TOKEN:
        if msg['severity'] <= 10:
            msg['priv_msg_type'] = 0
        else:
            msg['priv_msg_type'] = 1
        len_sqlstate = tds_get_byte(tds)
        msg['sql_state'] = tds_get_n(tds, len_sqlstate)
        has_eed = tds_get_byte(tds)
        # junk status and transaction state
        tds_get_smallint(tds)
    elif marker == TDS_INFO_TOKEN:
        msg['priv_msg_type'] = 0
    elif marker == TDS_ERROR_TOKEN:
        msg['priv_msg_type'] = 1
    else:
        logger.error('tds_process_msg() called with unknown marker "{0}"'.format(marker))
    logger.debug('tds_process_msg() reading message {0} from server'.format(msg['msgno']))
    msg['message'] = tds_get_string(tds, tds_get_smallint(tds))
    # server name
    msg['server'] = tds_get_string(tds, tds_get_byte(tds))
    if not msg['server'] and tds.login:
        msg['server'] = tds.server_name
    # stored proc name if available
    msg['proc_name'] = tds_get_string(tds, tds_get_byte(tds))
    msg['line_number'] = tds_get_int(tds) if IS_TDS72_PLUS(tds) else tds_get_smallint(tds)
    if not msg['sql_state']:
        #msg['sql_state'] = tds_alloc_lookup_sqlstate(tds, msg['msgno'])
        pass
    # in case extended error data is sent, we just try to discard it
    if has_eed:
        while True:
            next_marker = tds_get_byte(tds)
            if next_marker in (TDS5_PARAMFMT_TOKEN, TDS5_PARAMFMT2_TOKEN, TDS5_PARAMS_TOKEN):
                tds_process_default_tokens(tds, next_marker)
            else:
                break
        tds_unget_byte(tds)

    # call msg_handler

    # special case
    if marker == TDS_EED_TOKEN and tds.cur_dyn and tds.is_mssql() and msg['msgno'] == 2782:
        tds.cur_dyn.emulated = 1
    elif marker == TDS_INFO_TOKEN and msg['msgno'] == 16954 and \
            tds.is_mssql() and tds.internal_sp_called == TDS_SP_CURSOROPEN and\
            tds.cur_cursor:
                # here mssql say "Executing SQL directly; no cursor." opening cursor
                    pass
    else:
        # EED can be followed to PARAMFMT/PARAMS, do not store it in dynamic
        tds.cur_dyn = None
        if tds_get_ctx(tds).msg_handler:
            logger.debug('tds_process_msg() calling client msg handler')
            tds_get_ctx(tds).msg_handler(tds_get_ctx(tds), tds, msg)
        elif msg['msgno']:
            logger.warn(u'Msg {msgno}, Severity {severity}, State {state}, Server {server}, Line {line_number}\n{message}'.format(**msg))

_SERVER_TO_CLIENT_MAPPING = {
    0x07000000: TDS70,
    0x07010000: TDS71,
    0x71000001: TDS71rev1,
    TDS72: TDS72,
    TDS73A: TDS73A,
    TDS73B: TDS73B,
    TDS74: TDS74,
    }

def tds_process_login_tokens(tds):
    succeed = False
    logger.debug('tds_process_login_tokens()')
    ver = {}
    while True:
        marker = tds_get_byte(tds)
        logger.debug('looking for login token, got  {0:x}({1})'.format(marker, tds_token_name(marker)))
        if marker == TDS_LOGINACK_TOKEN:
            tds.tds71rev1 = 0
            size = tds_get_smallint(tds)
            ack = tds_get_byte(tds)
            version = tds_get_uint_be(tds)
            ver['reported'] = version
            tds.tds_version = _SERVER_TO_CLIENT_MAPPING[version]
            if tds.tds_version == TDS71rev1:
                tds.tds71rev1 = True
            if ver['reported'] == TDS70:
                ver['name'] = '7.0'
            elif ver['reported'] == TDS71:
                ver['name'] = '2000'
            elif ver['reported'] == TDS71rev1:
                ver['name'] = '2000 SP1'
            elif ver['reported'] == TDS72:
                ver['name'] = '2005'
            elif ver['reported'] == TDS73A:
                ver['name'] = '2008 (no NBCROW of fSparseColumnSet)'
            elif ver['reported'] == TDS73B:
                ver['name'] = '2008'
            elif version == TDS74:
                ver['name'] = '2012'
            else:
                ver['name'] = 'unknown'
            logger.debug('server reports TDS version {0:x}'.format(version))
            # get server product name
            # ignore product name length, some servers seem to set it incorrectly
            tds_get_byte(tds)
            product_version = 0
            size -= 10
            if IS_TDS7_PLUS(tds):
                product_version = 0x80000000
                tds.product_name = tds_get_string(tds, size/2)
            elif IS_TDS5_PLUS(tds):
                tds.product_name = tds_get_string(tds, size)
            else:
                tds.product_name = tds_get_string(tds, size)
            product_version = tds_get_uint_be(tds)
            # MSSQL 6.5 and 7.0 seem to return strange values for this
            # using TDS 4.2, something like 5F 06 32 FF for 6.50
            tds_conn(tds).product_version = product_version
            logger.debug('Product version {0:x}'.format(product_version))
            # TDS 5.0 reports 5 on success 6 on failure
            # TDS 4.2 reports 1 on success and is not present of failure
            if ack == 5 or ack == 1:
                succeed = True
            if tds.authentication:
                tds.authentication = None
        else:
            tds_process_default_tokens(tds, marker)
        if marker == TDS_DONE_TOKEN:
            break
    tds.spid = tds.rows_affected
    if tds.spid == 0:
        tds_set_spid(tds)
    return succeed

# process all streams.
# tds_process_tokens() is called after submitting a query with
# tds_submit_query() and is responsible for calling the routines to
# populate tds->res_info if appropriate (some query have no result sets)
# @param tds A pointer to the TDSSOCKET structure managing a client/server operation.
# @param result_type A pointer to an integer variable which 
#        tds_process_tokens sets to indicate the current type of result.
#  @par
#  <b>Values that indicate command status</b>
#  <table>
#   <tr><td>TDS_DONE_RESULT</td><td>The results of a command have been completely processed. 
# 					This command returned no rows.</td></tr>
#   <tr><td>TDS_DONEPROC_RESULT</td><td>The results of a  command have been completely processed.  
# 					This command returned rows.</td></tr>
#   <tr><td>TDS_DONEINPROC_RESULT</td><td>The results of a  command have been completely processed.  
# 					This command returned rows.</td></tr>
#  </table>
#  <b>Values that indicate results information is available</b>
#  <table><tr>
#    <td>TDS_ROWFMT_RESULT</td><td>Regular Data format information</td>
#    <td>tds->res_info now contains the result details ; tds->current_results now points to that data</td>
#   </tr><tr>
#    <td>TDS_COMPUTEFMT_ RESULT</td><td>Compute data format information</td>
#    <td>tds->comp_info now contains the result data; tds->current_results now points to that data</td>
#   </tr><tr>
#    <td>TDS_DESCRIBE_RESULT</td><td></td>
#    <td></td>
#  </tr></table>
#  <b>Values that indicate data is available</b>
#  <table><tr>
#   <td><b>Value</b></td><td><b>Meaning</b></td><td><b>Information returned</b></td>
#   </tr><tr>
#    <td>TDS_ROW_RESULT</td><td>Regular row results</td>
#    <td>1 or more rows of regular data can now be retrieved</td>
#   </tr><tr>
#    <td>TDS_COMPUTE_RESULT</td><td>Compute row results</td>
#    <td>A single row of compute data can now be retrieved</td>
#   </tr><tr>
#    <td>TDS_PARAM_RESULT</td><td>Return parameter results</td>
#    <td>param_info or cur_dyn->params contain returned parameters</td>
#   </tr><tr>
#    <td>TDS_STATUS_RESULT</td><td>Stored procedure status results</td>
#    <td>tds->ret_status contain the returned code</td>
#  </tr></table>
# @param flag Flags to select token type to stop/return
# @todo Complete TDS_DESCRIBE_RESULT description
# @retval TDS_SUCCESS if a result set is available for processing.
# @retval TDS_FAIL on error.
# @retval TDS_NO_MORE_RESULTS if all results have been completely processed.
# @retval anything returned by one of the many functions it calls.  :-(
#/
def tds_process_tokens(tds, flag):
    parent = {'result_type': 0, 'return_flag': 0}
    done_flags = 0
    #TDSPARAMINFO *pinfo = NULL;
    #TDSCOLUMN   *curcol;
    #TDSRET rc;
    saved_rows_affected = tds.rows_affected
    #TDS_INT ret_status;
    cancel_seen = 0
    import tds as tdsflags

    def SET_RETURN(ret, f):
        parent['result_type'] = ret
        parent['return_flag'] = getattr(tdsflags, 'TDS_RETURN_' + f) | getattr(tdsflags, 'TDS_STOPAT_' + f)
        if flag & getattr(tdsflags, 'TDS_STOPAT_' + f):
            tds_unget_byte(tds)
            logger.debug("tds_process_tokens::SET_RETURN stopping on current token")
            return False
        return True

    CHECK_TDS_EXTRA(tds)

    #tdsdump_log(TDS_DBG_FUNC, "tds_process_tokens(%p, %p, %p, 0x%x)\n", tds, result_type, done_flags, flag)

    if tds.state == TDS_IDLE:
        logger.debug("tds_process_tokens() state is COMPLETED")
        return TDS_NO_MORE_RESULTS, TDS_DONE_RESULT, done_flags

    if tds_set_state(tds, TDS_READING) != TDS_READING:
        raise Exception('TDS_FAIL')
    try:
        rc = TDS_SUCCESS
        while True:
            marker = tds_get_byte(tds)
            logger.info("processing result tokens.  marker is  {0:x}({1})".format(marker, tds_token_name(marker)))
            if marker == TDS7_RESULT_TOKEN:
                #
                # If we're processing the results of a cursor fetch
                # from sql server we don't want to pass back the
                # TDS_ROWFMT_RESULT to the calling API
                #
                if tds.internal_sp_called == TDS_SP_CURSORFETCH:
                    rc = tds7_process_result(tds)
                    marker = tds_get_byte(tds)
                    if marker != TDS_TABNAME_TOKEN:
                        tds_unget_byte(tds);
                    else:
                        rc = tds_process_tabname(tds);
                else:
                    if SET_RETURN(TDS_ROWFMT_RESULT, 'ROWFMT'):
                        rc = tds7_process_result(tds)
                        # handle browse information (if presents)
                        marker = tds_get_byte(tds)
                        if marker != TDS_TABNAME_TOKEN:
                            tds_unget_byte(tds)
                            rc = TDS_SUCCESS
                        else:
                            rc = tds_process_tabname(tds)
            elif marker == TDS_RESULT_TOKEN:
                if SET_RETURN(TDS_ROWFMT_RESULT, 'ROWFMT'):
                    rc = tds_process_result(tds)
            elif marker == TDS_ROWFMT2_TOKEN:
                if SET_RETURN(TDS_ROWFMT_RESULT, 'ROWFMT'):
                    rc = tds5_process_result(tds)
            elif marker == TDS_COLNAME_TOKEN:
                rc = tds_process_col_name(tds)
            elif marker == TDS_COLFMT_TOKEN:
                if SET_RETURN(TDS_ROWFMT_RESULT, 'ROWFMT'):
                    rc = tds_process_col_fmt(tds)
                    # handle browse information (if present)
                    marker = tds_get_byte(tds)
                    if marker == TDS_TABNAME_TOKEN:
                        rc = tds_process_tabname(tds)
                    else:
                        tds_unget_byte(tds)
            elif marker == TDS_PARAM_TOKEN:
                tds_unget_byte(tds)
                if tds.internal_sp_called:
                    logger.debug("processing parameters for sp {0}".formst(tds.internal_sp_called))
                    while True:
                        marker = tds_get_byte(tds)
                        if marker != TDS_PARAM_TOKEN:
                            break
                        logger.debug("calling tds_process_param_result")
                        pinfo = tds_process_param_result(tds)
                    tds_unget_byte(tds)
                    logger.debug("{0} hidden return parameters".format(pinfo.num_cols if pinfo else -1))
                    if pinfo and pinfo.num_cols > 0:
                        curcol = pinfo.columns[0]
                        if tds.internal_sp_called == TDS_SP_CURSOROPEN and tds.cur_cursor:
                            cursor = tds.cur_cursor

                            cursor.cursor_id = curcol.value
                            logger.debug("stored internal cursor id {0}".format(cursor.cursor_id))
                            cursor.srv_status &= ~(TDS_CUR_ISTAT_CLOSED|TDS_CUR_ISTAT_OPEN|TDS_CUR_ISTAT_DEALLOC)
                            cursor.srv_status |= TDS_CUR_ISTAT_OPEN if cursor.cursor_id else TDS_CUR_ISTAT_CLOSED|TDS_CUR_ISTAT_DEALLOC
                        if (tds.internal_sp_called == TDS_SP_PREPARE or tds.internal_sp_called == TDS_SP_PREPEXEC)\
                            and tds.cur_dyn and tds.cur_dyn.num_id == 0 and curcol.value:
                                tds.cur_dyn.num_id = curcol.value
                else:
                    if SET_RETURN(TDS_PARAM_RESULT, 'PROC'):
                        rc = tds_process_param_result_tokens(tds)
            elif marker == TDS_COMPUTE_NAMES_TOKEN:
                rc = tds_process_compute_names(tds)
            elif marker == TDS_COMPUTE_RESULT_TOKEN:
                if SET_RETURN(TDS_COMPUTEFMT_RESULT, 'COMPUTEFMT'):
                    rc = tds_process_compute_result(tds)
            elif marker == TDS7_COMPUTE_RESULT_TOKEN:
                if SET_RETURN(TDS_COMPUTEFMT_RESULT, 'COMPUTEFMT'):
                    rc = tds7_process_compute_result(tds)
            elif marker in (TDS_ROW_TOKEN, TDS_NBC_ROW_TOKEN):
                # overstepped the mark...
                if tds.cur_cursor:
                    cursor = tds.cur_cursor

                    tds.current_results = cursor.res_info
                    logger.debug("tds_process_tokens(). set current_results to cursor->res_info")
                else:
                    # assure that we point to row, not to compute
                    if tds.res_info:
                        tds.current_results = tds.res_info
                # I don't know when this it's false but it happened, also server can send garbage...
                if tds.current_results:
                    tds.current_results.rows_exist = 1
                if SET_RETURN(TDS_ROW_RESULT, 'ROW'):
                    if marker == TDS_NBC_ROW_TOKEN:
                        rc = tds_process_nbcrow(tds)
                    else:
                        rc = tds_process_row(tds)
            elif marker == TDS_CMP_ROW_TOKEN:
                # I don't know when this it's false but it happened, also server can send garbage...
                if tds.res_info:
                    tds.res_info.rows_exist = 1
                if SET_RETURN(TDS_COMPUTE_RESULT, 'COMPUTE'):
                    rc = tds_process_compute(tds, NULL)
            elif marker == TDS_RETURNSTATUS_TOKEN:
                ret_status = tds_get_int(tds)
                marker = tds_peek(tds)
                if marker in (TDS_PARAM_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONE_TOKEN, TDS5_PARAMFMT_TOKEN, TDS5_PARAMFMT2_TOKEN):
                    if tds.internal_sp_called:
                        # TODO perhaps we should use ret_status ??
                        pass
                    else:
                        # TODO optimize
                        flag &= ~TDS_STOPAT_PROC
                        if SET_RETURN(TDS_STATUS_RESULT, 'PROC'):
                            tds.has_status = 1
                            tds.ret_status = ret_status
                            logger.debug("tds_process_tokens: return status is {0}".format(tds.ret_status))
                            rc = TDS_SUCCESS
            elif marker == TDS5_DYNAMIC_TOKEN:
                # process acknowledge dynamic
                tds.cur_dyn = tds_process_dynamic(tds)
                # special case, prepared statement cannot be prepared
                if tds.cur_dyn and not tds.cur_dyn.emulated:
                    marker = tds_get_byte(tds);
                    if marker == TDS_EED_TOKEN:
                        tds_process_msg(tds, marker)
                        if tds.cur_dyn and tds.cur_dyn.emulated:
                            marker = tds_get_byte(tds)
                            if marker == TDS_DONE_TOKEN:
                                rc, done_flags = tds_process_end(tds, marker)
                                done_flags &= ~TDS_DONE_ERROR
                                # FIXME warning to macro expansion
                                SET_RETURN(TDS_DONE_RESULT, 'DONE')
                            else:
                                tds_unget_byte(tds);
                    else:
                        tds_unget_byte(tds);
            elif marker == TDS5_PARAMFMT_TOKEN:
                if SET_RETURN(TDS_DESCRIBE_RESULT, 'PARAMFMT'):
                    rc = tds_process_dyn_result(tds)
            elif marker == TDS5_PARAMFMT2_TOKEN:
                if SET_RETURN(TDS_DESCRIBE_RESULT, 'PARAMFMT'):
                    rc = tds5_process_dyn_result2(tds)
            elif marker == TDS5_PARAMS_TOKEN:
                if SET_RETURN(TDS_PARAM_RESULT, 'PROC'):
                    rc = tds_process_params_result_token(tds)
            elif marker == TDS_CURINFO_TOKEN:
                rc = tds_process_cursor_tokens(tds)
            elif marker == TDS_DONE_TOKEN:
                if SET_RETURN(TDS_DONE_RESULT, 'DONE'):
                    rc, done_flags = tds_process_end(tds, marker)
            elif marker == TDS_DONEPROC_TOKEN:
                if SET_RETURN(TDS_DONEPROC_RESULT, 'DONE'):
                    rc, done_flags = tds_process_end(tds, marker)
                    if tds.internal_sp_called in (0, TDS_SP_PREPARE,
                            TDS_SP_PREPEXEC, TDS_SP_EXECUTE,
                            TDS_SP_UNPREPARE, TDS_SP_EXECUTESQL):
                        pass
                    elif tds.internal_sp_called == TDS_SP_CURSOROPEN:
                            parent['result_type'] = TDS_DONE_RESULT
                            tds.rows_affected = saved_rows_affected
                    elif tds.internal_sp_called == TDS_SP_CURSORCLOSE:
                        logger.debug("TDS_SP_CURSORCLOSE")
                        if tds.cur_cursor:
                            cursor = tds.cur_cursor

                            cursor.srv_status &= ~TDS_CUR_ISTAT_OPEN
                            cursor.srv_status |= TDS_CUR_ISTAT_CLOSED|TDS_CUR_ISTAT_DECLARED
                            if cursor.status.dealloc == TDS_CURSOR_STATE_SENT:
                                tds_cursor_deallocated(tds, cursor)
                        parent['result_type'] = TDS_NO_MORE_RESULTS
                        rc = TDS_NO_MORE_RESULTS
                    else:
                        parent['result_type'] = TDS_NO_MORE_RESULTS
                        rc = TDS_NO_MORE_RESULTS
            elif marker == TDS_DONEINPROC_TOKEN:
                if tds.internal_sp_called in (TDS_SP_CURSOROPEN, TDS_SP_CURSORFETCH, TDS_SP_PREPARE, TDS_SP_CURSORCLOSE):
                    rc, done_flags = tds_process_end(tds, marker)
                    if tds.rows_affected != TDS_NO_COUNT:
                        saved_rows_affected = tds.rows_affected
                else:
                    if SET_RETURN(TDS_DONEINPROC_RESULT, 'DONE'):
                        rc, done_flags = tds_process_end(tds, marker)
            elif marker in (TDS_ERROR_TOKEN, TDS_INFO_TOKEN, TDS_EED_TOKEN):
                if SET_RETURN(TDS_MSG_RESULT, 'MSG'):
                    rc = tds_process_default_tokens(tds, marker)
            else:
                if SET_RETURN(TDS_OTHERS_RESULT, 'OTHERS'):
                    rc = tds_process_default_tokens(tds, marker)

            cancel_seen |= tds.in_cancel
            if cancel_seen:
                # during cancel handle all tokens
                flag = TDS_HANDLE_ALL

            if parent['return_flag'] & flag != 0:
                if tds.state != TDS_IDLE:
                    tds_set_state(tds, TDS_PENDING)
                return rc, parent['result_type'], done_flags

            if tds.state == TDS_IDLE:
                return (TDS_CANCELLED if cancel_seen else TDS_NO_MORE_RESULTS), parent['result_type'], done_flags

            if tds.state == TDS_DEAD:
                # TODO free all results ??
                return TDS_FAIL, parent['result_type'], done_flags
    except:
        tds_set_state(tds, TDS_PENDING)
        raise

#/**
# * \remarks Process the incoming token stream until it finds
# * an end token (DONE, DONEPROC, DONEINPROC) with the cancel flag set.
# * At that point the connection should be ready to handle a new query.
# */
def tds_process_cancel(tds):
    CHECK_TDS_EXTRA(tds);

    # silly cases, nothing to do
    if not tds.in_cancel:
        return TDS_SUCCESS
    # TODO handle cancellation sending data
    if tds.state != TDS_PENDING:
        return TDS_SUCCESS

    # TODO support TDS5 cancel, wait for cancel packet first, then wait for done
    while True:
        rc, result_type, _ = tds_process_tokens(tds, 0)

        if rc == TDS_FAIL:
            raise Exception('TDS_FAIL')
        elif rc in (TDS_CANCELLED, TDS_SUCCESS, TDS_NO_MORE_RESULTS):
            return TDS_SUCCESS

#/**
# * tds7_process_result() is the TDS 7.0 result set processing routine.  It 
# * is responsible for populating the tds->res_info structure.
# * This is a TDS 7.0 only function
# */
def tds7_process_result(tds):
    #int col, num_cols;
    #TDSRET result;
    #TDSRESULTINFO *info;

    CHECK_TDS_EXTRA(tds)
    logger.debug("processing TDS7 result metadata.")

    # read number of columns and allocate the columns structure

    num_cols = tds_get_smallint(tds)

    # This can be a DUMMY results token from a cursor fetch

    if num_cols == -1:
        logger.debug("no meta data")
        return TDS_SUCCESS

    tds_free_all_results(tds)
    tds.rows_affected = TDS_NO_COUNT

    info = tds_alloc_results(num_cols)
    tds.current_results = info
    if tds.cur_cursor:
        tds_free_results(tds.cur_cursor.res_info)
        tds.cur_cursor.res_info = info
        logger.debug("set current_results to cursor->res_info")
    else:
        tds.res_info = info
        logger.debug("set current_results ({0} column{1}) to tds->res_info".format(num_cols, ('' if num_cols==1 else "s")))

    #
    # loop through the columns populating COLINFO struct from
    # server response
    #
    logger.debug("setting up {0} columns".format(num_cols))
    for col in range(num_cols):
        curcol = info.columns[col]
        tds7_get_data_info(tds, curcol)
    if num_cols > 0:
        dashes = "------------------------------"
        #tdsdump_log(TDS_DBG_INFO1, " %-20s %-15s %-15s %-7s\n", "name", "size/wsize", "type/wtype", "utype");
        #tdsdump_log(TDS_DBG_INFO1, " %-20s %15s %15s %7s\n", dashes+10, dashes+30-15, dashes+30-15, dashes+30-7);
    for col in range(num_cols):
        curcol = info.columns[col]

        if curcol.column_name:
            name = curcol.column_name
        #tdsdump_log(TDS_DBG_INFO1, " %-20s %7d/%-7d %7d/%-7d %7d\n", 
        #                                name, 
        #                                curcol->column_size, curcol->on_server.column_size, 
        #                                curcol->column_type, curcol->on_server.column_type, 
        #                                curcol->column_usertype);

    # all done now allocate a row for tds_process_row to use
    result = tds_alloc_row(info)
    CHECK_TDS_EXTRA(tds)
    return result

#/**
# * Read data information from wire
# * \param tds state information for the socket and the TDS protocol
# * \param curcol column where to store information
# */
def tds7_get_data_info(tds, curcol):
    #int colnamelen;

    CHECK_TDS_EXTRA(tds)
    CHECK_COLUMN_EXTRA(curcol)

    # User defined data type of the column
    curcol.column_usertype = tds_get_int(tds) if IS_TDS72_PLUS(tds) else tds_get_smallint(tds)

    curcol.column_flags = tds_get_smallint(tds) # Flags

    curcol.column_nullable = curcol.column_flags & 0x01;
    curcol.column_writeable = (curcol.column_flags & 0x08) > 0
    curcol.column_identity = (curcol.column_flags & 0x10) > 0

    tds_set_column_type(tds, curcol, tds_get_byte(tds)) # sets "cardinal" type

    curcol.column_timestamp = (curcol.column_type == SYBBINARY and curcol.column_usertype == TDS_UT_TIMESTAMP)

    curcol.funcs.get_info(tds, curcol)

    # Adjust column size according to client's encoding
    #curcol.on_server.column_size = curcol.column_size

    # NOTE adjustements must be done after curcol->char_conv initialization
    adjust_character_column_size(tds, curcol)

    #
    # under 7.0 lengths are number of characters not
    # number of bytes...tds_get_string handles this
    #
    curcol.column_name = tds_get_string(tds, tds_get_byte(tds))

    logger.debug("tds7_get_data_info: \n"
                "\tcolname = %s (%d bytes)\n"
                "\ttype = %d (%s)\n"
                "\tserver's type = %d (%s)\n"
                "\tcolumn_varint_size = %d" % (
                curcol.column_name, len(curcol.column_name), 
                curcol.column_type, tds_prtype(curcol.column_type),
                curcol.on_server.column_type, tds_prtype(curcol.on_server.column_type),
                curcol.column_varint_size))

    CHECK_COLUMN_EXTRA(curcol)

    return TDS_SUCCESS

#
# Adjust column size according to client's encoding 
#
def adjust_character_column_size(tds, curcol):
    CHECK_TDS_EXTRA(tds)
    CHECK_COLUMN_EXTRA(curcol)

    if is_unicode_type(curcol.on_server.column_type):
        curcol.char_conv = tds.char_convs[client2ucs2]

    # Sybase UNI(VAR)CHAR fields are transmitted via SYBLONGBINARY and in UTF-16
    if curcol.on_server.column_type == SYBLONGBINARY and \
            curcol.column_usertype in (USER_UNICHAR_TYPE, USER_UNIVARCHAR_TYPE):
        sybase_utf = "UTF-16LE"

        curcol.char_conv = tds_iconv_get(tds, tds.char_convs[client2ucs2].client_charset.name, sybase_utf)

        # fallback to UCS-2LE
        # FIXME should be useless. Does not works always
        if not curcol.char_conv:
            curcol.char_conv = tds.char_convs[client2ucs2]

    # FIXME: and sybase ??
    if not curcol.char_conv and IS_TDS7_PLUS(tds) and is_ascii_type(curcol.on_server.column_type):
        curcol.char_conv = tds.char_convs[client2server_chardata]

    if not USE_ICONV(tds) or not curcol.char_conv:
        return

    curcol.on_server.column_size = curcol.column_size;
    curcol.column_size = determine_adjusted_size(curcol.char_conv, curcol.column_size)

    logger.debug("adjust_character_column_size:\n"
                 "\tServer charset: %s\n"
                 "\tServer column_size: %d\n"
                 "\tClient charset: %s\n"
                 "\tClient column_size: %d\n", 
                 curcol.char_conv['server_charset']['name'], 
                 curcol.on_server.column_size, 
                 curcol.char_conv['client_charset']['name'],
                 curcol.column_size)

def determine_adjusted_size(char_conv, column_size):
    return column_size

_prtype_map = dict((
            (SYBAOPAVG, "avg"),
            (SYBAOPCNT, "count"),
            (SYBAOPMAX, "max"),
            (SYBAOPMIN, "min"),
            (SYBAOPSUM, "sum"),
            (SYBBINARY, "binary"),
            (SYBLONGBINARY, "longbinary"),
            (SYBBIT, "bit"),
            (SYBBITN, "bit-null"),
            (SYBCHAR, "char"),
            (SYBDATETIME4, "smalldatetime"),
            (SYBDATETIME, "datetime"),
            (SYBDATETIMN, "datetime-null"),
            (SYBDECIMAL, "decimal"),
            (SYBFLT8, "float"),
            (SYBFLTN, "float-null"),
            (SYBIMAGE, "image"),
            (SYBINT1, "tinyint"),
            (SYBINT2, "smallint"),
            (SYBINT4, "int"),
            (SYBINT8, "bigint"),
            (SYBINTN, "integer-null"),
            (SYBMONEY4, "smallmoney"),
            (SYBMONEY, "money"),
            (SYBMONEYN, "money-null"),
            (SYBNTEXT, "UCS-2 text"),
            (SYBNVARCHAR, "UCS-2 varchar"),
            (SYBNUMERIC, "numeric"),
            (SYBREAL, "real"),
            (SYBTEXT, "text"),
            (SYBUNIQUE, "uniqueidentifier"),
            (SYBVARBINARY, "varbinary"),
            (SYBVARCHAR, "varchar"),
            (SYBVARIANT, "variant"),
            (SYBVOID, "void"),
            (XSYBBINARY, "xbinary"),
            (XSYBCHAR, "xchar"),
            (XSYBNCHAR, "x UCS-2 char"),
            (XSYBNVARCHAR, "x UCS-2 varchar"),
            (XSYBVARBINARY, "xvarbinary"),
            (XSYBVARCHAR, "xvarchar"),
            (SYBMSDATE, "date"),
            (SYBMSTIME, "time"),
            )
        )

def tds_prtype(token):
    return _prtype_map.get(token, '')

def tds_swap_numeric(num):
    # swap the sign
    arr_sign = chr(0) if ord(num.array[0]) else chr(1)
    # swap the data
    arr_prec = tds_swap_bytes(num.array[1:], tds_numeric_bytes_per_prec[num.precision] - 1)
    arr_rest = num.array[1+tds_numeric_bytes_per_prec[num.precision] - 1:]
    return ''.join([arr_sign, arr_prec, arr_rest])
