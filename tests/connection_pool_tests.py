import unittest
import settings
import pytds

LIVE_TEST = getattr(settings, "LIVE_TEST", True)


def test_broken_connection_in_pool():
    """
    Broken connection in the pool should not cause issues when
    it is attempted to be reused
    """
    # first clear pool of any connections
    pytds.connection_pool._pool.clear()

    # create extra connection, it is needed to be able to kill other connections
    extra_conn = pytds.connect(**settings.CONNECT_KWARGS, autocommit=True)

    # Now create one connection and get underlying connection
    with pytds.connect(**settings.CONNECT_KWARGS, autocommit=True) as conn:
        sess = conn._tds_socket.main_session

    # kill this connection, need to use another connection to do that
    spid = sess.execute_scalar("select @@spid")
    with extra_conn.cursor() as cur:
        cur.execute(f"kill {spid}")

    # create new connection, it should attempt to use connection from the pool
    # it should detect that connection is bad and create new one
    with pytds.connect(**settings.CONNECT_KWARGS, autocommit=True) as conn:
        with conn.cursor() as cur:
            assert 1 == cur.execute_scalar("select 1")
    # cleanup
    extra_conn.close()
