import logging
import traceback
from tdsproto import *
from tds import _Column
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

def tds_process_auth(tds):
    r = tds._reader
    w = tds._writer
    pdu_size = r.get_smallint()
    if not tds.authentication:
        raise Error('Got unexpected token')
    packet = tds.authentication.handle_next(r.readall(pdu_size))
    if packet:
        w.write(packet)
        w.flush()

def tds_process_default_tokens(tds, marker):
    r = tds._reader
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
        tok_size = r.get_smallint()
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
            #    type = r.get_byte()
            #    size = r.get_byte()
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
            tds_conn(tds).capabilities = r.readall(min(tok_size, TDS_MAX_CAPABILITY))
            # PARAM_TOKEN can be returned inserting text in db, to return new timestamp
    elif marker == TDS_PARAM_TOKEN:
        r.unget_byte()
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
        r.skip(r.get_smallint())
    elif marker == TDS_TABNAME_TOKEN: # used for FOR BROWSE query
        return tds_process_tabname(tds)
    elif marker == TDS_COLINFO_TOKEN:
        return tds_process_colinfo(tds, None, 0)
    elif marker == TDS_ORDERBY2_TOKEN:
        logger.debug("Eating %s token", tds_token_name(marker))
        r.skip(r.get_int())
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
    info = tds.current_results
    #if not info:
    #    raise Exception('TDS_FAIL')

    #assert len(info.columns) > 0

    info.row_count += 1
    for curcol in info.columns:
        #logger.debug("tds_process_row(): reading column %d" % i)
        curcol.value = curcol.funcs.get_data(tds, curcol)
    return TDS_SUCCESS

# NBC=null bitmap compression row
# http://msdn.microsoft.com/en-us/library/dd304783(v=prot.20).aspx
def tds_process_nbcrow(tds):
    r = tds._reader
    info = tds.current_results
    if not info:
        raise Exception('TDS_FAIL')
    assert len(info.columns) > 0
    info.row_count += 1

    # reading bitarray for nulls, 1 represent null values for
    # corresponding fields
    nbc = r.readall((len(info.columns) + 7) / 8)
    for i, curcol in enumerate(info.columns):
        if ord(nbc[i/8]) & (1 << i%8):
            curcol.value = None
        else:
            curcol.value = curcol.funcs.get_data(tds, curcol)
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
    r = tds._reader
    status = r.get_usmallint()
    cur_cmd = r.get_usmallint()
    more_results = status & TDS_DONE_MORE_RESULTS != 0
    was_cancelled = status & TDS_DONE_CANCELLED != 0
    error = status & TDS_DONE_ERROR != 0
    done_count_valid = status & TDS_DONE_COUNT != 0
    logger.debug('tds_process_end: more_results = {0}\n'
            '\t\twas_cancelled = {1}\n'
            '\t\terror = {2}\n'
            '\t\tdone_count_valid = {3}'.format(more_results, was_cancelled, error, done_count_valid))
    if tds.res_info:
        tds.res_info.more_results = more_results
        if not tds.current_results:
            tds.current_results = tds.res_info
    rows_affected = r.get_int8() if IS_TDS72_PLUS(tds) else r.get_int()
    logger.debug('\t\trows_affected = {0}'.format(rows_affected))
    if was_cancelled or (not more_results and not tds.in_cancel):
        logger.debug('tds_process_end() state set to TDS_IDLE')
        tds.in_cancel = False
        tds.set_state(TDS_IDLE)
    if tds.is_dead():
        raise Exception('TDS_FAIL')
    if done_count_valid:
        tds.rows_affected = rows_affected
    else:
        tds.rows_affected = -1
    return (TDS_CANCELLED if was_cancelled else TDS_SUCCESS), status

def tds_process_env_chg(tds):
    r = tds._reader
    size = r.get_smallint()
    type = r.get_byte()
    if type == TDS_ENV_SQLCOLLATION:
        size = r.get_byte()
        logger.debug("tds_process_env_chg(): {0} bytes of collation data received".format(size))
        logger.debug("tds.collation was {0}".format(tds.conn.collation))
        tds.conn.collation = r.get_collation()
        r.skip(size - 5)
        #tds7_srv_charset_changed(tds, tds.conn.collation)
        logger.debug("tds.collation now {0}".format(tds.conn.collation))
        # discard old one
        r.skip(r.get_byte())
    elif type == TDS_ENV_BEGINTRANS:
        size = r.get_byte()
        # TODO: parse transaction
        tds.conn.tds72_transaction = r.readall(8)
        r.skip(r.get_byte())
    elif type == TDS_ENV_COMMITTRANS or type == TDS_ENV_ROLLBACKTRANS:
        tds.conn.tds72_transaction = None
        r.skip(r.get_byte())
        r.skip(r.get_byte())
    elif type == TDS_ENV_PACKSIZE:
        newval = r.read_ucs2(r.get_byte())
        oldval = r.read_ucs2(r.get_byte())
        new_block_size = int(newval)
        if new_block_size >= 512:
            logger.info("changing block size from {0} to {1}".format(oldval, new_block_size))
            #
            # Is possible to have a shrink if server limits packet
            # size more than what we specified
            #
            # Reallocate buffer if possible (strange values from server or out of memory) use older buffer */
            tds._writer.bufsize = new_block_size
    elif type == TDS_ENV_DATABASE:
        newval = r.read_ucs2(r.get_byte())
        oldval = r.read_ucs2(r.get_byte())
        tds.conn.env.database = newval
    elif type == TDS_ENV_LANG:
        newval = r.read_ucs2(r.get_byte())
        oldval = r.read_ucs2(r.get_byte())
        tds.conn.env.language = newval
    elif type == TDS_ENV_CHARSET:
        newval = r.read_ucs2(r.get_byte())
        oldval = r.read_ucs2(r.get_byte())
        logger.debug("server indicated charset change to \"{0}\"\n".format(newval))
        tds.conn.env.charset = newval
        tds_srv_charset_changed(tds, newval)
    elif type == TDS_ENV_DB_MIRRORING_PARTNER:
        newval = r.read_ucs2(r.get_byte())
        oldval = r.read_ucs2(r.get_byte())

    else:
        # discard byte values, not still supported
        # TODO support them
        # discard new one
        r.skip(r.get_byte())
        # discard old one
        r.skip(r.get_byte())


def tds_process_msg(tds, marker):
    r = tds._reader
    size = r.get_smallint()
    msg = {}
    msg['marker'] = marker
    msg['msgno'] = r.get_int()
    msg['state'] = r.get_byte()
    msg['severity'] = r.get_byte()
    msg['sql_state'] = None
    has_eed = False
    if marker == TDS_EED_TOKEN:
        if msg['severity'] <= 10:
            msg['priv_msg_type'] = 0
        else:
            msg['priv_msg_type'] = 1
        len_sqlstate = r.get_byte()
        msg['sql_state'] = r.readall(len_sqlstate)
        has_eed = r.get_byte()
        # junk status and transaction state
        r.get_smallint()
    elif marker == TDS_INFO_TOKEN:
        msg['priv_msg_type'] = 0
    elif marker == TDS_ERROR_TOKEN:
        msg['priv_msg_type'] = 1
    else:
        logger.error('tds_process_msg() called with unknown marker "{0}"'.format(marker))
    logger.debug('tds_process_msg() reading message {0} from server'.format(msg['msgno']))
    msg['message'] = r.read_ucs2(r.get_smallint())
    # server name
    msg['server'] = r.read_ucs2(r.get_byte())
    if not msg['server'] and tds.login:
        msg['server'] = tds.server_name
    # stored proc name if available
    msg['proc_name'] = r.read_ucs2(r.get_byte())
    msg['line_number'] = r.get_int() if IS_TDS72_PLUS(tds) else r.get_smallint()
    if not msg['sql_state']:
        #msg['sql_state'] = tds_alloc_lookup_sqlstate(tds, msg['msgno'])
        pass
    # in case extended error data is sent, we just try to discard it
    if has_eed:
        while True:
            next_marker = r.get_byte()
            if next_marker in (TDS5_PARAMFMT_TOKEN, TDS5_PARAMFMT2_TOKEN, TDS5_PARAMS_TOKEN):
                tds_process_default_tokens(tds, next_marker)
            else:
                break
        r.unget_byte()

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
    tds.messages.append(msg)

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
    r = tds._reader
    succeed = False
    logger.debug('tds_process_login_tokens()')
    ver = {}
    while True:
        marker = r.get_byte()
        logger.debug('looking for login token, got  {0:x}({1})'.format(marker, tds_token_name(marker)))
        if marker == TDS_LOGINACK_TOKEN:
            tds.tds71rev1 = 0
            size = r.get_smallint()
            ack = r.get_byte()
            version = r.get_uint_be()
            ver['reported'] = version
            tds.conn.tds_version = _SERVER_TO_CLIENT_MAPPING[version]
            if tds.conn.tds_version == TDS71rev1:
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
            r.get_byte()
            product_version = 0
            size -= 10
            if IS_TDS7_PLUS(tds):
                product_version = 0x80000000
                tds.conn.product_name = r.read_ucs2(size/2)
            elif IS_TDS5_PLUS(tds):
                raise NotImplementedError()
                #tds.product_name = tds_get_string(tds, size)
            else:
                raise NotImplementedError()
                #tds.product_name = tds_get_string(tds, size)
            product_version = r.get_uint_be()
            # MSSQL 6.5 and 7.0 seem to return strange values for this
            # using TDS 4.2, something like 5F 06 32 FF for 6.50
            tds.conn.product_version = product_version
            logger.debug('Product version {0:x}'.format(product_version))
            # TDS 5.0 reports 5 on success 6 on failure
            # TDS 4.2 reports 1 on success and is not present of failure
            if ack == 5 or ack == 1:
                succeed = True
            if tds.conn.authentication:
                tds.conn.authentication.close()
                tds.conn.authentication = None
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
    saved_rows_affected = tds.rows_affected
    cancel_seen = 0
    import tds as tdsflags
    r = tds._reader

    def SET_RETURN(ret, f):
        parent['result_type'] = ret
        return_flag = getattr(tdsflags, 'TDS_RETURN_' + f)
        stopat_flag = getattr(tdsflags, 'TDS_STOPAT_' + f)
        parent['return_flag'] = return_flag | stopat_flag
        if flag & stopat_flag:
            r.unget_byte()
            logger.debug("tds_process_tokens::SET_RETURN stopping on current token")
            return False
        return True

    if tds.state == TDS_IDLE:
        logger.debug("tds_process_tokens() state is COMPLETED")
        return TDS_NO_MORE_RESULTS, TDS_DONE_RESULT, done_flags

    if tds.set_state(TDS_READING) != TDS_READING:
        raise Exception('TDS_FAIL')
    try:
        rc = TDS_SUCCESS
        while True:
            marker = r.get_byte()
            logger.info("processing result tokens.  marker is  {0:x}({1})".format(marker, tds_token_name(marker)))
            if marker == TDS7_RESULT_TOKEN:
                #
                # If we're processing the results of a cursor fetch
                # from sql server we don't want to pass back the
                # TDS_ROWFMT_RESULT to the calling API
                #
                if tds.internal_sp_called == TDS_SP_CURSORFETCH:
                    rc = tds7_process_result(tds)
                    marker = r.get_byte()
                    if marker != TDS_TABNAME_TOKEN:
                        r.unget_byte();
                    else:
                        rc = tds_process_tabname(tds);
                else:
                    if SET_RETURN(TDS_ROWFMT_RESULT, 'ROWFMT'):
                        rc = tds7_process_result(tds)
                        # handle browse information (if presents)
                        marker = r.get_byte()
                        if marker != TDS_TABNAME_TOKEN:
                            r.unget_byte()
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
                    marker = r.get_byte()
                    if marker == TDS_TABNAME_TOKEN:
                        rc = tds_process_tabname(tds)
                    else:
                        r.unget_byte()
            elif marker == TDS_PARAM_TOKEN:
                r.unget_byte()
                if tds.internal_sp_called:
                    logger.debug("processing parameters for sp {0}".formst(tds.internal_sp_called))
                    while True:
                        marker = r.get_byte()
                        if marker != TDS_PARAM_TOKEN:
                            break
                        logger.debug("calling tds_process_param_result")
                        pinfo = tds_process_param_result(tds)
                    r.unget_byte()
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
                ret_status = r.get_int()
                marker = r.peek()
                if marker in (TDS_PARAM_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONE_TOKEN, TDS5_PARAMFMT_TOKEN, TDS5_PARAMFMT2_TOKEN):
                    if tds.internal_sp_called:
                        # TODO perhaps we should use ret_status ??
                        pass
                    else:
                        # TODO optimize
                        flag &= ~TDS_STOPAT_PROC
                        if SET_RETURN(TDS_STATUS_RESULT, 'PROC'):
                            tds.has_status = True
                            tds.ret_status = ret_status
                            logger.debug("tds_process_tokens: return status is {0}".format(tds.ret_status))
                            rc = TDS_SUCCESS
            elif marker == TDS5_DYNAMIC_TOKEN:
                # process acknowledge dynamic
                tds.cur_dyn = tds_process_dynamic(tds)
                # special case, prepared statement cannot be prepared
                if tds.cur_dyn and not tds.cur_dyn.emulated:
                    marker = r.get_byte();
                    if marker == TDS_EED_TOKEN:
                        tds_process_msg(tds, marker)
                        if tds.cur_dyn and tds.cur_dyn.emulated:
                            marker = r.get_byte()
                            if marker == TDS_DONE_TOKEN:
                                rc, done_flags = tds_process_end(tds, marker)
                                done_flags &= ~TDS_DONE_ERROR
                                # FIXME warning to macro expansion
                                SET_RETURN(TDS_DONE_RESULT, 'DONE')
                            else:
                                r.unget_byte()
                    else:
                        r.unget_byte()
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
                    tds.set_state(TDS_PENDING)
                return rc, parent['result_type'], done_flags

            if tds.state == TDS_IDLE:
                return (TDS_CANCELLED if cancel_seen else TDS_NO_MORE_RESULTS), parent['result_type'], done_flags

            if tds.state == TDS_DEAD:
                # TODO free all results ??
                return TDS_FAIL, parent['result_type'], done_flags
    except:
        tds.set_state(TDS_PENDING)
        raise

#/**
# * \remarks Process the incoming token stream until it finds
# * an end token (DONE, DONEPROC, DONEINPROC) with the cancel flag set.
# * At that point the connection should be ready to handle a new query.
# */
def tds_process_cancel(tds):
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

def get_api_coltype(coltype):
    if coltype in (SYBBIT, SYBINT1, SYBINT2, SYBINT4, SYBINT8, SYBINTN,
            SYBREAL, SYBFLT8, SYBFLTN):
        return NUMBER
    elif coltype in (SYBMONEY, SYBMONEY4, SYBMONEYN, SYBNUMERIC,
            SYBDECIMAL):
        return DECIMAL
    elif coltype in (SYBDATETIME, SYBDATETIME4, SYBDATETIMN):
        return DATETIME
    elif coltype in (SYBVARCHAR, SYBCHAR, SYBTEXT,
        XSYBNVARCHAR, XSYBNCHAR, SYBNTEXT,
        XSYBVARCHAR, XSYBCHAR):
        return STRING
    else:
        return BINARY

from tds import _Results


#/**
# * tds7_process_result() is the TDS 7.0 result set processing routine.  It 
# * is responsible for populating the tds->res_info structure.
# * This is a TDS 7.0 only function
# */
def tds7_process_result(tds):
    r = tds._reader
    logger.debug("processing TDS7 result metadata.")

    # read number of columns and allocate the columns structure

    num_cols = r.get_smallint()

    # This can be a DUMMY results token from a cursor fetch

    if num_cols == -1:
        logger.debug("no meta data")
        return TDS_SUCCESS

    tds.res_info = None
    tds.param_info = None
    tds.has_status = False
    tds.ret_status = False
    tds.current_results = None
    tds.rows_affected = TDS_NO_COUNT

    tds.current_results = info = _Results()
    if tds.cur_cursor:
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
    header_tuple = []
    for col in range(num_cols):
        curcol = _Column()
        info.columns.append(curcol)
        tds7_get_data_info(tds, curcol)
        coltype = get_api_coltype(curcol.column_type)
        precision = curcol.column_prec if hasattr(curcol, 'column_prec') else None
        scale = curcol.column_scale if hasattr(curcol, 'column_scale') else None
        header_tuple.append((curcol.column_name, coltype, None, None, precision, scale, curcol.column_nullable))
    info.native_descr = tuple((col.column_name, col.column_type)
            for col in tds.res_info.columns)
    info.description = tuple(header_tuple)
    return info 

def tds_get_type_info(tds, curcol):
    r = tds._reader
    # User defined data type of the column
    curcol.column_usertype = r.get_uint() if IS_TDS72_PLUS(tds) else r.get_usmallint()

    curcol.column_flags = r.get_usmallint() # Flags

    curcol.column_nullable = curcol.column_flags & 0x01;
    curcol.column_writeable = (curcol.column_flags & 0x08) > 0
    curcol.column_identity = (curcol.column_flags & 0x10) > 0

    tds_set_column_type(tds, curcol, r.get_byte()) # sets "cardinal" type

    curcol.column_timestamp = (curcol.column_type == SYBBINARY and curcol.column_usertype == TDS_UT_TIMESTAMP)

    curcol.funcs.get_info(tds, curcol)

#/**
# * Read data information from wire
# * \param tds state information for the socket and the TDS protocol
# * \param curcol column where to store information
# */
def tds7_get_data_info(tds, curcol):
    r = tds._reader
    tds_get_type_info(tds, curcol)

    # Adjust column size according to client's encoding
    #curcol.column_size = curcol.column_size

    # NOTE adjustements must be done after curcol.char_codec initialization
    adjust_character_column_size(tds, curcol)

    #
    # under 7.0 lengths are number of characters not
    # number of bytes... read_ucs2 handles this
    #
    curcol.column_name = r.read_ucs2(r.get_byte())

    return TDS_SUCCESS

#
# Adjust column size according to client's encoding 
#
def adjust_character_column_size(tds, curcol):
    if is_unicode_type(curcol.column_type):
        curcol.char_codec = ucs2_codec

    # Sybase UNI(VAR)CHAR fields are transmitted via SYBLONGBINARY and in UTF-16
    if curcol.column_type == SYBLONGBINARY and \
            curcol.column_usertype in (USER_UNICHAR_TYPE, USER_UNIVARCHAR_TYPE):

        curcol.char_codec = ucs2_codec
    # FIXME: and sybase ??
    if not curcol.char_codec and IS_TDS7_PLUS(tds) and is_ascii_type(curcol.column_type):
        curcol.char_codec = tds.conn.collation.get_codec()

    if not curcol.char_codec:
        return

    curcol.column_size = curcol.column_size;
    curcol.column_size = determine_adjusted_size(curcol.char_codec, curcol.column_size)

def determine_adjusted_size(char_codec, column_size):
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

def tds_process_param_result_tokens(tds):
    r = tds._reader
    while True:
        token = r.get_byte()
        if token == TDS_PARAM_TOKEN:
            ordinal = r.get_usmallint()
            name = r.read_ucs2(r.get_byte())
            status = r.get_byte() # 1 - OUTPUT of sp, 2 - result of udf
            param = _Column()
            param.column_name = name
            tds_get_type_info(tds, param)
            param.value = param.funcs.get_data(tds, param)
            tds.output_params[ordinal] = param
        else:
            r.unget_byte()
            return
