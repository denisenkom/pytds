import logging
from tds import *
from threadsafe import *

logger = logging.getLogger(__name__)

def tds_set_state(tds, state):
    assert 0 <= state < len(state_names)
    assert 0 <= tds.state < len(state_names)
    prior_state = tds.state
    if state == prior_state:
        return state
    if state == TDS_PENDING:
        if prior_state in (TDS_READING, TDS_QUERYING):
            tds.state = TDS_PENDING
            tds_mutex_unlock(tds.wire_mtx)
        else:
            logger.error('logic error: cannot chage query state from {0} to {1}'.\
                    format(state_names[prior_state], state_names[state]))
    elif state == TDS_READING:
        # transition to READING are valid only from PENDING
        if tds_mutex_trylock(tds.wire_mtx):
            return tds.state
        if tds.state != TDS_PENDING:
            tds_mutex_unlock(tds.wire_mtx)
            logger.error('logic error: cannot change query state from {0} to {1}'.\
                    format(state_names[prior_state], state_names[state]))
        else:
            tds.state = state
    elif state == TDS_IDLE:
        if prior_state == TDS_DEAD and tds_get_s(tds) is None:
            logger.error('logic error: cannot change query state from {0} to {1}'.\
                    format(state_names[prior_state], state_names[state]))
        elif prior_state in (TDS_READING, TDS_QUERYING):
            tds_mutex_unlock(tds.wire_mtx)
        tds.state = state
    elif state == TDS_DEAD:
        if prior_state in (TDS_READING, TDS_QUERYING):
            tds_mutex_unlock(tds.wire_mtx)
        tds.state = state
    elif state == TDS_QUERYING:
        #check_tds_extra(tds)
        if tds_mutex_trylock(tds.wire_mtx):
            return tds.state
        if tds.state == TDS_DEAD:
            tds_mutex_unlock(tds.wire_mtx)
            logger.error('logic error: cannot change query state from {0} to {1}'.\
                    format(state_names[prior_state], state_names[state]))
        elif tds.state != TDS_IDLE:
            tds_mutex_unlock(tds.wire_mtx)
            logger.error('logic error: cannot change query state from {0} to {1}'.\
                    format(state_names[prior_state], state_names[state]))
        else:
            #tds_free_all_results(tds)
            tds.rows_affected = TDS_NO_COUNT
            #tds_release_cursor
            tds.internal_sp_called = 0
            tds.state = state
    else:
        assert False
    #check_tds_extra(tds)
    return tds.state

def tds_swap_bytes(buf, size):
    return buf[0:size][::-1]
