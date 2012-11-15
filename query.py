from write import *
from tds_checks import *
from tds import *
from util import *
from tdsproto import *
from net import *

def START_QUERY(tds):
    if IS_TDS72_PLUS(tds):
        tds_start_query(tds)

tds72_query_start = str(bytearray([
    #/* total length */
    0x16, 0, 0, 0,
    #/* length */
    0x12, 0, 0, 0,
    #/* type */
    0x02, 0,
    #/* transaction */
    0, 0, 0, 0, 0, 0, 0, 0,
    #/* request count */
    1, 0, 0, 0]))

def tds_start_query(tds):
    tds_put_s(tds, tds72_query_start[:10])
    assert len(tds.tds72_transaction) == 8
    tds_put_s(tds, tds.tds72_transaction)
    assert len(tds72_query_start[10 + 8:]) == 4
    tds_put_s(tds, tds72_query_start[10 + 8:])

def tds_query_flush_packet(tds):
    # TODO depend on result ??
    tds_set_state(tds, TDS_PENDING)
    return tds_flush_packet(tds)

#
# tds_submit_query() sends a language string to the database server for
# processing.  TDS 4.2 is a plain text message with a packet type of 0x01,
# TDS 7.0 is a unicode string with packet type 0x01, and TDS 5.0 uses a 
# TDS_LANGUAGE_TOKEN to encapsulate the query and a packet type of 0x0f.
# \param tds state information for the socket and the TDS protocol
# \param query language query to submit
# \return TDS_FAIL or TDS_SUCCESS
#
def tds_submit_query(tds, query):
    return tds_submit_query_params(tds, query, None)

#
# tds_submit_query_params() sends a language string to the database server for
# processing.  TDS 4.2 is a plain text message with a packet type of 0x01,
# TDS 7.0 is a unicode string with packet type 0x01, and TDS 5.0 uses a
# TDS_LANGUAGE_TOKEN to encapsulate the query and a packet type of 0x0f.
# \param tds state information for the socket and the TDS protocol
# \param query  language query to submit
# \param params parameters of query
# \return TDS_FAIL or TDS_SUCCESS
#
def tds_submit_query_params(tds, query, params):
    #size_t query_len;
    CHECK_TDS_EXTRA(tds)
    if params:
        CHECK_PARAMINFO_EXTRA(params)

    if not query:
        raise Exception('TDS_FAIL')

    if tds_set_state(tds, TDS_QUERYING) != TDS_QUERYING:
        raise Exception('TDS_FAIL')

    if IS_TDS50(tds):
        new_query = None
        # are there '?' style parameters ?
        if tds_next_placeholder(query):
            new_query = tds5_fix_dot_query(query, params)
            if new_query is None:
                tds_set_state(tds, TDS_IDLE)
                raise Exception('TDS_FAIL')
            query = new_query

        tds.out_flag = TDS_NORMAL
        tds_put_byte(tds, TDS_LANGUAGE_TOKEN)
        # TODO ICONV use converted size, not input size and convert string
        TDS_PUT_INT(tds, len(query) + 1)
        tds_put_byte(tds, 1 if params else 0) # 1 if there are params, 0 otherwise
        tds_put_s(tds, query)
        if params:
            # add on parameters
            tds_put_params(tds, params, TDS_PUT_DATA_USE_NAME if params.columns[0].column_name else 0)
    elif not IS_TDS7_PLUS(tds) or not params or not params.num_cols:
            tds.out_flag = TDS_QUERY
            START_QUERY(tds)
            tds_put_string(tds, query)
    else:
        #TDSCOLUMN *param;
        #size_t definition_len;
        #int count, i;
        #char *param_definition;
        #size_t converted_query_len;
        #const char *converted_query;

        converted_query = tds_convert_string(tds, tds.char_convs[client2ucs2], query)
        if not converted_query:
            tds_set_state(tds, TDS_IDLE);
            raise Exception('TDS_FAIL')

        count = tds_count_placeholders_ucs2le(converted_query)

        if not count:
            param_definition = tds7_build_param_def_from_params(tds, converted_query, params)
            if not param_definition:
                tds_set_state(tds, TDS_IDLE)
                raise Exception('TDS_FAIL')
        else:
            #
            # TODO perhaps functions that calls tds7_build_param_def_from_query
            # should call also tds7_build_param_def_from_params ??
            #
            param_definition = tds7_build_param_def_from_query(tds, converted_query, params)
            if not param_definition:
                tds_set_state(tds, TDS_IDLE)
                raise Exception('TDS_FAIL')

        tds.out_flag = TDS_RPC
        START_QUERY(tds)
        # procedure name
        if IS_TDS71_PLUS(tds):
            tds_put_smallint(tds, -1)
            tds_put_smallint(tds, TDS_SP_EXECUTESQL)
        else:
            tds_put_smallint(tds, 13)
            TDS_PUT_N_AS_UCS2(tds, "sp_executesql")
        tds_put_smallint(tds, 0)

        # string with sql statement
        if not count:
            tds_put_byte(tds, 0)
            tds_put_byte(tds, 0)
            tds_put_byte(tds, SYBNTEXT) # must be Ntype
            TDS_PUT_INT(tds, len(converted_query))
            if IS_TDS71_PLUS(tds):
                tds_put_s(tds, tds.collation)
            TDS_PUT_INT(tds, len(converted_query))
            tds_put_s(tds, converted_query)
        else:
            tds7_put_query_params(tds, converted_query)
        tds7_put_params_definition(tds, param_definition)
        for param in params.columns:
            # TODO check error
            tds_put_data_info(tds, param, 0);
            if tds_put_data(tds, param) != TDS_SUCCESS:
                raise Exception('TDS_FAIL')
        tds.internal_sp_called = TDS_SP_EXECUTESQL
    return tds_query_flush_packet(tds)

#/**
# * tds_send_cancel() sends an empty packet (8 byte header only)
# * tds_process_cancel should be called directly after this.
# * \param tds state information for the socket and the TDS protocol
# * \remarks
# *	tcp will either deliver the packet or time out. 
# *	(TIME_WAIT determines how long it waits between retries.)  
# *	
# *	On sending the cancel, we may get EAGAIN.  We then select(2) until we know
# *	either 1) it succeeded or 2) it didn't.  On failure, close the socket,
# *	tell the app, and fail the function.  
# *	
# *	On success, we read(2) and wait for a reply with select(2).  If we get
# *	one, great.  If the client's timeout expires, we tell him, but all we can
# *	do is wait some more or give up and close the connection.  If he tells us
# *	to cancel again, we wait some more.  
# */
def tds_send_cancel(tds):
    #TDSRET rc;
    if TDS_MUTEX_TRYLOCK(tds.wire_mtx):
        # TODO check
        # signal other socket
        raise Exception('not implemented')
        #tds_conn(tds).s_signal.send((void*) &tds, sizeof(tds))
        return TDS_SUCCESS

    CHECK_TDS_EXTRA(tds);

    logger.debug("tds_send_cancel: %sin_cancel and %sidle".format(
                            ('' if tds.in_cancel else "not "), ('' if tds.state == TDS_IDLE else "not ")))

    # one cancel is sufficient
    if tds.in_cancel or tds.state == TDS_IDLE:
        TDS_MUTEX_UNLOCK(tds.wire_mtx)
        return TDS_SUCCESS

    rc = tds_put_cancel(tds)
    TDS_MUTEX_UNLOCK(tds.wire_mtx)

    return rc
