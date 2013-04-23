import logging
import traceback
from .tdsproto import *
from .tds import *
from .tds import _Results, _Column, _applytz
from . import tds as tdsflags

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
    packet = tds.authentication.handle_next(readall(r, pdu_size))
    if packet:
        w.write(packet)
        w.flush()


def tds_process_default_tokens(tds, marker):
    r = tds._reader
    #logger.debug('tds_process_default_tokens() marker is {0:x}({1})'.format(marker, tds_token_name(marker)))
    if tds.is_dead():
        #logger.debug('leaving tds_process_login_tokens() connection dead')
        tds.close()
        raise Exception('TDS_FAIL')
    if marker == TDS_AUTH_TOKEN:
        return tds_process_auth(tds)
    elif marker == TDS_ENVCHANGE_TOKEN:
        return tds_process_env_chg(tds)
    elif marker in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
        rc, _ = tds.process_end(marker)
        return rc
    elif marker in (TDS_ERROR_TOKEN, TDS_INFO_TOKEN, TDS_EED_TOKEN):
        tds.process_msg(marker)
    elif marker == TDS_CAPABILITY_TOKEN:
        # TODO split two part of capability and use it
        tok_size = r.get_smallint()
        # vicm
        #
        # Sybase 11.0 servers return the wrong length in the capability packet, causing use to read
        # past the done packet.
        #
        if not TDS_IS_MSSQL(tds) and tds_conn(tds).product_version < TDS_SYB_VER(12, 0, 0):
            raise NotImplementedError
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
            tds_conn(tds).capabilities = readall(r, min(tok_size, TDS_MAX_CAPABILITY))
            # PARAM_TOKEN can be returned inserting text in db, to return new timestamp
    elif marker == TDS_PARAM_TOKEN:
        r.unget_byte()
        return tds.process_param_result_tokens()
    elif marker == TDS7_RESULT_TOKEN:
        return tds.tds7_process_result()
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
        return tds.process_row()
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
        #logger.warning("Eating %s token", tds_token_name(marker))
        r.skip(r.get_smallint())
    elif marker == TDS_TABNAME_TOKEN:  # used for FOR BROWSE query
        return tds_process_tabname(tds)
    elif marker == TDS_COLINFO_TOKEN:
        return tds_process_colinfo(tds, None, 0)
    elif marker == TDS_ORDERBY2_TOKEN:
        #logger.warning("Eating %s token", tds_token_name(marker))
        r.skip(r.get_int())
    elif marker == TDS_NBC_ROW_TOKEN:
        return tds_process_nbcrow(tds)
    else:
        tds.close()
        raise Error('Invalid TDS marker: {0}({0:x}) {1}'.format(marker, ''.join(traceback.format_stack())))


def tds_process_env_chg(tds):
    r = tds._reader
    size = r.get_smallint()
    type = r.get_byte()
    if type == TDS_ENV_SQLCOLLATION:
        size = r.get_byte()
        #logger.debug("tds_process_env_chg(): {0} bytes of collation data received".format(size))
        #logger.debug("tds.collation was {0}".format(tds.conn.collation))
        tds.conn.collation = r.get_collation()
        r.skip(size - 5)
        #tds7_srv_charset_changed(tds, tds.conn.collation)
        #logger.debug("tds.collation now {0}".format(tds.conn.collation))
        # discard old one
        r.skip(r.get_byte())
    elif type == TDS_ENV_BEGINTRANS:
        size = r.get_byte()
        # TODO: parse transaction
        tds.conn.tds72_transaction = r.get_uint8()
        r.skip(r.get_byte())
    elif type == TDS_ENV_COMMITTRANS or type == TDS_ENV_ROLLBACKTRANS:
        tds.conn.tds72_transaction = 0
        r.skip(r.get_byte())
        r.skip(r.get_byte())
    elif type == TDS_ENV_PACKSIZE:
        newval = r.read_ucs2(r.get_byte())
        oldval = r.read_ucs2(r.get_byte())
        new_block_size = int(newval)
        if new_block_size >= 512:
            #logger.info("changing block size from {0} to {1}".format(oldval, new_block_size))
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
        #logger.debug("server indicated charset change to \"{0}\"\n".format(newval))
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
                tds.conn.product_name = r.read_ucs2(size // 2)
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
#           This command returned no rows.</td></tr>
#   <tr><td>TDS_DONEPROC_RESULT</td><td>The results of a  command have been completely processed.
#           This command returned rows.</td></tr>
#   <tr><td>TDS_DONEINPROC_RESULT</td><td>The results of a  command have been completely processed.
#           This command returned rows.</td></tr>
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
#
def tds_process_tokens(tds, flag):
    parent = {'result_type': 0, 'return_flag': 0}
    done_flags = 0
    saved_rows_affected = tds.rows_affected
    cancel_seen = 0
    r = tds._reader

    def SET_RETURN(ret, return_flag, stopat_flag):
        parent['result_type'] = ret
        parent['return_flag'] = return_flag | stopat_flag
        if flag & stopat_flag:
            r.unget_byte()
            #logger.debug("tds_process_tokens::SET_RETURN stopping on current token")
            return False
        return True

    if tds.state == TDS_IDLE:
        #logger.debug("tds_process_tokens() state is COMPLETED")
        return TDS_NO_MORE_RESULTS, TDS_DONE_RESULT, done_flags

    with tds.state_context(TDS_READING):
        rc = TDS_SUCCESS
        while True:
            marker = r.get_byte()
            #logger.info("processing result tokens.  marker is  {0:x}({1})".format(marker, tds_token_name(marker)))
            if marker == TDS7_RESULT_TOKEN:
                #
                # If we're processing the results of a cursor fetch
                # from sql server we don't want to pass back the
                # TDS_ROWFMT_RESULT to the calling API
                #
                if tds.internal_sp_called == TDS_SP_CURSORFETCH:
                    rc = tds.tds7_process_result()
                    marker = r.get_byte()
                    if marker != TDS_TABNAME_TOKEN:
                        r.unget_byte()
                    else:
                        rc = tds_process_tabname(tds)
                else:
                    if SET_RETURN(TDS_ROWFMT_RESULT, tdsflags.TDS_RETURN_ROWFMT, tdsflags.TDS_STOPAT_ROWFMT):
                        rc = tds.tds7_process_result()
                        # handle browse information (if presents)
                        marker = r.get_byte()
                        if marker != TDS_TABNAME_TOKEN:
                            r.unget_byte()
                            rc = TDS_SUCCESS
                        else:
                            rc = tds_process_tabname(tds)
            elif marker == TDS_RESULT_TOKEN:
                if SET_RETURN(TDS_ROWFMT_RESULT, tdsflags.TDS_RETURN_ROWFMT, tdsflags.TDS_STOPAT_ROWFMT):
                    rc = tds_process_result(tds)
            elif marker == TDS_ROWFMT2_TOKEN:
                if SET_RETURN(TDS_ROWFMT_RESULT, tdsflags.TDS_RETURN_ROWFMT, tdsflags.TDS_STOPAT_ROWFMT):
                    rc = tds5_process_result(tds)
            elif marker == TDS_COLNAME_TOKEN:
                rc = tds_process_col_name(tds)
            elif marker == TDS_COLFMT_TOKEN:
                if SET_RETURN(TDS_ROWFMT_RESULT, tdsflags.TDS_RETURN_ROWFMT, tdsflags.TDS_STOPAT_ROWFMT):
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
                    #logger.debug("processing parameters for sp {0}".formst(tds.internal_sp_called))
                    while True:
                        marker = r.get_byte()
                        if marker != TDS_PARAM_TOKEN:
                            break
                        #logger.debug("calling tds_process_param_result")
                        pinfo = tds_process_param_result(tds)
                    r.unget_byte()
                    #logger.debug("{0} hidden return parameters".format(pinfo.num_cols if pinfo else -1))
                    if pinfo and pinfo.num_cols > 0:
                        curcol = pinfo.columns[0]
                        if tds.internal_sp_called == TDS_SP_CURSOROPEN and tds.cur_cursor:
                            cursor = tds.cur_cursor

                            cursor.cursor_id = curcol.value
                            #logger.debug("stored internal cursor id {0}".format(cursor.cursor_id))
                            cursor.srv_status &= ~(TDS_CUR_ISTAT_CLOSED | TDS_CUR_ISTAT_OPEN | TDS_CUR_ISTAT_DEALLOC)
                            cursor.srv_status |= TDS_CUR_ISTAT_OPEN if cursor.cursor_id else TDS_CUR_ISTAT_CLOSED | TDS_CUR_ISTAT_DEALLOC
                        if (tds.internal_sp_called == TDS_SP_PREPARE or tds.internal_sp_called == TDS_SP_PREPEXEC)\
                                and tds.cur_dyn and tds.cur_dyn.num_id == 0 and curcol.value:
                            tds.cur_dyn.num_id = curcol.value
                else:
                    if SET_RETURN(TDS_PARAM_RESULT, tdsflags.TDS_RETURN_PROC, tdsflags.TDS_STOPAT_PROC):
                        rc = tds.process_param_result_tokens()
            elif marker == TDS_COMPUTE_NAMES_TOKEN:
                rc = tds_process_compute_names(tds)
            elif marker == TDS_COMPUTE_RESULT_TOKEN:
                if SET_RETURN(TDS_COMPUTEFMT_RESULT, tdsflags.TDS_RETURN_COMPUTEFMT, tdsflags.TDS_STOPAT_COMPUTEFMT):
                    rc = tds_process_compute_result(tds)
            elif marker == TDS7_COMPUTE_RESULT_TOKEN:
                if SET_RETURN(TDS_COMPUTEFMT_RESULT, tdsflags.TDS_RETURN_COMPUTEFMT, tdsflags.TDS_STOPAT_COMPUTEFMT):
                    rc = tds7_process_compute_result(tds)
            elif marker in (TDS_ROW_TOKEN, TDS_NBC_ROW_TOKEN):
                # overstepped the mark...
                if tds.cur_cursor:
                    cursor = tds.cur_cursor

                    tds.current_results = cursor.res_info
                    #logger.debug("tds_process_tokens(). set current_results to cursor->res_info")
                else:
                    # assure that we point to row, not to compute
                    if tds.res_info:
                        tds.current_results = tds.res_info
                # I don't know when this it's false but it happened, also server can send garbage...
                if tds.current_results:
                    tds.current_results.rows_exist = 1
                if SET_RETURN(TDS_ROW_RESULT, tdsflags.TDS_RETURN_ROW, tdsflags.TDS_STOPAT_ROW):
                    if marker == TDS_NBC_ROW_TOKEN:
                        rc = tds.process_nbcrow()
                    else:
                        rc = tds.process_row()
            elif marker == TDS_CMP_ROW_TOKEN:
                # I don't know when this it's false but it happened, also server can send garbage...
                if tds.res_info:
                    tds.res_info.rows_exist = 1
                if SET_RETURN(TDS_COMPUTE_RESULT, tdsflags.TDS_RETURN_COMPUTE, tdsflags.TDS_STOPAT_COMPUTE):
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
                        if SET_RETURN(TDS_STATUS_RESULT, tdsflags.TDS_RETURN_PROC, tdsflags.TDS_STOPAT_PROC):
                            tds.has_status = True
                            tds.ret_status = ret_status
                            #logger.debug("tds_process_tokens: return status is {0}".format(tds.ret_status))
                            rc = TDS_SUCCESS
            elif marker == TDS5_DYNAMIC_TOKEN:
                # process acknowledge dynamic
                tds.cur_dyn = tds_process_dynamic(tds)
                # special case, prepared statement cannot be prepared
                if tds.cur_dyn and not tds.cur_dyn.emulated:
                    marker = r.get_byte()
                    if marker == TDS_EED_TOKEN:
                        tds.process_msg(marker)
                        if tds.cur_dyn and tds.cur_dyn.emulated:
                            marker = r.get_byte()
                            if marker == TDS_DONE_TOKEN:
                                rc, done_flags = tds.process_end(marker)
                                done_flags &= ~TDS_DONE_ERROR
                                # FIXME warning to macro expansion
                                SET_RETURN(TDS_DONE_RESULT, tdsflags.TDS_RETURN_DONE, tdsflags.TDS_STOPAT_DONE)
                            else:
                                r.unget_byte()
                    else:
                        r.unget_byte()
            elif marker == TDS5_PARAMFMT_TOKEN:
                if SET_RETURN(TDS_DESCRIBE_RESULT, tdsflags.TDS_RETURN_PARAMFMT, tdsflags.TDS_STOPAT_PARAMFMT):
                    rc = tds_process_dyn_result(tds)
            elif marker == TDS5_PARAMFMT2_TOKEN:
                if SET_RETURN(TDS_DESCRIBE_RESULT, tdsflags.TDS_RETURN_PARAMFMT, tdsflags.TDS_STOPAT_PARAMFMT):
                    rc = tds5_process_dyn_result2(tds)
            elif marker == TDS5_PARAMS_TOKEN:
                if SET_RETURN(TDS_PARAM_RESULT, tdsflags.TDS_RETURN_PROC, tdsflags.TDS_STOPAT_PROC):
                    rc = tds_process_params_result_token(tds)
            elif marker == TDS_CURINFO_TOKEN:
                rc = tds_process_cursor_tokens(tds)
            elif marker == TDS_DONE_TOKEN:
                if SET_RETURN(TDS_DONE_RESULT, tdsflags.TDS_RETURN_DONE, tdsflags.TDS_STOPAT_DONE):
                    rc, done_flags = tds.process_end(marker)
            elif marker == TDS_DONEPROC_TOKEN:
                if SET_RETURN(TDS_DONEPROC_RESULT, tdsflags.TDS_RETURN_DONE, tdsflags.TDS_STOPAT_DONE):
                    rc, done_flags = tds.process_end(marker)
                    if tds.internal_sp_called in (0, TDS_SP_PREPARE,
                                                  TDS_SP_PREPEXEC, TDS_SP_EXECUTE,
                                                  TDS_SP_UNPREPARE, TDS_SP_EXECUTESQL):
                        pass
                    elif tds.internal_sp_called == TDS_SP_CURSOROPEN:
                            parent['result_type'] = TDS_DONE_RESULT
                            tds.rows_affected = saved_rows_affected
                    elif tds.internal_sp_called == TDS_SP_CURSORCLOSE:
                        #logger.debug("TDS_SP_CURSORCLOSE")
                        if tds.cur_cursor:
                            cursor = tds.cur_cursor

                            cursor.srv_status &= ~TDS_CUR_ISTAT_OPEN
                            cursor.srv_status |= TDS_CUR_ISTAT_CLOSED | TDS_CUR_ISTAT_DECLARED
                            if cursor.status.dealloc == TDS_CURSOR_STATE_SENT:
                                tds_cursor_deallocated(tds, cursor)
                        parent['result_type'] = TDS_NO_MORE_RESULTS
                        rc = TDS_NO_MORE_RESULTS
                    else:
                        parent['result_type'] = TDS_NO_MORE_RESULTS
                        rc = TDS_NO_MORE_RESULTS
            elif marker == TDS_DONEINPROC_TOKEN:
                if tds.internal_sp_called in (TDS_SP_CURSOROPEN, TDS_SP_CURSORFETCH, TDS_SP_PREPARE, TDS_SP_CURSORCLOSE):
                    rc, done_flags = tds.process_end(marker)
                    if tds.rows_affected != TDS_NO_COUNT:
                        saved_rows_affected = tds.rows_affected
                else:
                    if SET_RETURN(TDS_DONEINPROC_RESULT, tdsflags.TDS_RETURN_DONE, tdsflags.TDS_STOPAT_DONE):
                        rc, done_flags = tds.process_end(marker)
            elif marker in (TDS_ERROR_TOKEN, TDS_INFO_TOKEN, TDS_EED_TOKEN):
                if SET_RETURN(TDS_MSG_RESULT, tdsflags.TDS_RETURN_MSG, tdsflags.TDS_STOPAT_MSG):
                    rc = tds_process_default_tokens(tds, marker)
            else:
                if SET_RETURN(TDS_OTHERS_RESULT, tdsflags.TDS_RETURN_OTHERS, tdsflags.TDS_STOPAT_OTHERS):
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
    ))


def tds_prtype(token):
    return _prtype_map.get(token, '')
