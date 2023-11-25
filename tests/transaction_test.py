import pytds
import pytds.extensions
import settings
from fixtures import separate_db_connection
from utils import tran_count, does_table_exist


def test_rollback_commit():
    """
    Test calling rollback and commit with no changes
    """
    conn = pytds.connect(*settings.CONNECT_ARGS, **settings.CONNECT_KWARGS)
    cursor = conn.cursor()
    cursor.execute('select 1')
    conn.rollback()
    conn.commit()


def test_rollback_timeout_recovery(separate_db_connection):
    conn = separate_db_connection
    conn.autocommit = False
    with conn.cursor() as cur:
        cur.execute('''
        create table testtable_rollback (field int)
        ''')
        sql = 'insert into testtable_rollback values ' + ','.join(['(1)'] * 1000)
        for i in range(10):
            cur.execute(sql)

    conn._tds_socket.sock.settimeout(0.00001)
    try:
        conn.rollback()
    except:
        pass

    conn._tds_socket.sock.settimeout(10)
    cur = conn.cursor()
    cur.execute('select 1')
    cur.fetchall()


def test_commit_timeout_recovery(separate_db_connection):
    conn = separate_db_connection
    conn.autocommit = False
    with conn.cursor() as cur:
        try:
            cur.execute('drop table testtable_commit_rec')
        except:
            pass
        cur.execute('''
        create table testtable_commit_rec (field int)
        ''')
        sql = 'insert into testtable_commit_rec values ' + ','.join(['(1)'] * 1000)
        for i in range(10):
            cur.execute(sql)

    conn._tds_socket.sock.settimeout(0.00001)
    try:
        conn.commit()
    except:
        pass

    conn._tds_socket.sock.settimeout(10)
    cur = conn.cursor()
    cur.execute('select 1')
    cur.fetchall()


def test_autocommit_off(separate_db_connection):
    """
    Testing autocommit off mode, making sure that new transaction is started immediately after previous
    one is committed or rolled back
    """
    conn = separate_db_connection
    # second connection is used to observe effects of transaction on first connection
    conn2 = pytds.connect(**settings.CONNECT_KWARGS)
    conn2.autocommit = False
    assert not conn.autocommit
    conn2.rollback()
    with conn.cursor() as cur, conn2.cursor() as cur2:
        conn.isolation_level = pytds.extensions.ISOLATION_LEVEL_SNAPSHOT
        conn.rollback()
        conn2.isolation_level = pytds.extensions.ISOLATION_LEVEL_SNAPSHOT
        conn2.rollback()
        try:
            cur.execute('drop table test_autocommit')
        except:
            pass
        conn.commit()
        assert not does_table_exist(cursor=cur2, name='test_autocommit', database='test'), "table should not exist now since we ensured it is deleted"
        cur.execute('create table test_autocommit(field int)')
        conn.commit()
        assert does_table_exist(cursor=cur2, name='test_autocommit', database='test'), "table should exist now, since we committed creation"
        # New transaction should be started after committing previous transaction
        assert 1 == tran_count(cur)
        cur.execute('insert into test_autocommit(field) values(1)')
        assert 1 == tran_count(cur)
        cur.execute('select field from test_autocommit')
        row = cur.fetchone()
        assert cur2.execute("select * from test_autocommit").fetchall() == [], "should not see created row from another connection since it is not committed yet"

        # But using read uncommitted level we should see changes from different connection
        conn2.isolation_level = pytds.extensions.ISOLATION_LEVEL_READ_UNCOMMITTED
        conn2.rollback()
        assert cur2.execute("select * from test_autocommit").fetchall() == [(1,)]

        conn.rollback()
        assert 1 == tran_count(cur)
        cur.execute('select field from test_autocommit')
        row = cur.fetchone()
        assert not row


def test_autocommit_on(separate_db_connection):
    conn = separate_db_connection
    conn.autocommit = True
    with conn.cursor() as cur:
        # commit in autocommit mode should be a no-op
        conn.commit()
        # rollback in autocommit mode should be a no-op
        conn.rollback()
        cur.execute('insert into test_autocommit(field) values(1)')
        assert 0 == tran_count(cur)


def test_isolation_level(separate_db_connection):
    """
    Testing setting different isolation levels and verifying that they are set via querying MSSQL's
    sys.dm_exec_sessions view.
    """
    conn = separate_db_connection
    conn.autocommit = False
    with conn.cursor() as cur:
        for level in [
            pytds.extensions.ISOLATION_LEVEL_SERIALIZABLE,
            pytds.extensions.ISOLATION_LEVEL_SNAPSHOT,
            pytds.extensions.ISOLATION_LEVEL_READ_COMMITTED,
            pytds.extensions.ISOLATION_LEVEL_READ_UNCOMMITTED,
            pytds.extensions.ISOLATION_LEVEL_REPEATABLE_READ,
        ]:
            conn.isolation_level = level
            # rollback to force new transaction to start
            conn.rollback()
            assert level == cur.execute_scalar(
                'select transaction_isolation_level '
                'from sys.dm_exec_sessions where session_id = @@SPID'
            )


def test_transactions(separate_db_connection):
    conn = separate_db_connection
    conn.autocommit = False
    with conn.cursor() as cur:
        cur.execute('''
        create table testtable_trans (field datetime)
        ''')
        cur.execute("select object_id('testtable_trans')")
        assert (None,) != cur.fetchone()
        assert 1 == tran_count(cur)
        conn.rollback()
        assert 1 == tran_count(cur)
        cur.execute("select object_id('testtable_trans')")
        assert (None,) == cur.fetchone()

        cur.execute('''
        create table testtable_trans (field datetime)
        ''')

        conn.commit()

        cur.execute("select object_id('testtable_trans')")
        assert (None,) != cur.fetchone()

    with conn.cursor() as cur:
        cur.execute('''
        if object_id('testtable_trans') is not null
            drop table testtable_trans
        ''')
    conn.commit()


def test_manual_commit(separate_db_connection):
    conn = separate_db_connection
    conn.autocommit = False
    cur = conn.cursor()
    cur.execute("create table tbl(x int)")
    assert 1 == cur.execute_scalar("select @@trancount"), 'Should be in transaction even after errors'
    assert conn._tds_socket.tds72_transaction
    try:
        cur.execute("create table tbl(x int)")
    except pytds.OperationalError:
        pass
    trancount = cur.execute_scalar("select @@trancount")
    assert 1 == trancount, 'Should be in transaction even after errors'

    cur.execute("create table tbl(x int)")
    try:
        cur.execute("create table tbl(x int)")
    except:
        pass
    cur.callproc('sp_executesql', ('select @@trancount',))
    trancount, = cur.fetchone()
    assert 1 == trancount, 'Should be in transaction even after errors'
