from decimal import Decimal, getcontext
import pytest
import six
from six import StringIO, BytesIO
import pytds
import settings


@pytest.fixture(scope='module')
def db_connection():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs['database'] = 'master'
    return pytds.connect(*settings.CONNECT_ARGS, **kwargs)


@pytest.fixture
def cursor(db_connection):
    cursor = db_connection.cursor()
    yield cursor
    cursor.close()
    db_connection.rollback()


@pytest.fixture
def separate_db_connection():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs['database'] = 'master'
    conn = pytds.connect(*settings.CONNECT_ARGS, **kwargs)
    yield conn
    conn.close()


def test_integrity_error(cursor):
    cursor.execute('create table testtable_pk(pk int primary key)')
    cursor.execute('insert into testtable_pk values (1)')
    with pytest.raises(pytds.IntegrityError):
        cursor.execute('insert into testtable_pk values (1)')


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

    conn._conn.sock.settimeout(0.00001)
    try:
        conn.rollback()
    except:
        pass

    conn._conn.sock.settimeout(10)
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

    conn._conn.sock.settimeout(0.00001)
    try:
        conn.commit()
    except:
        pass

    conn._conn.sock.settimeout(10)
    cur = conn.cursor()
    cur.execute('select 1')
    cur.fetchall()


def test_autocommit(separate_db_connection):
    conn = separate_db_connection
    assert not conn.autocommit
    with conn.cursor() as cur:
        try:
            cur.execute('drop table test_autocommit')
        except:
            pass
        cur.execute('create table test_autocommit(field int)')
        conn.commit()
        assert 1 == conn._trancount()
        cur.execute('insert into test_autocommit(field) values(1)')
        assert 1 == conn._trancount()
        cur.execute('select field from test_autocommit')
        row = cur.fetchone()
        conn.rollback()
        cur.execute('select field from test_autocommit')
        row = cur.fetchone()
        assert not row

        conn.autocommit = True
        # commit in autocommit mode should be a no-op
        conn.commit()
        # rollback in autocommit mode should be a no-op
        conn.rollback()
        cur.execute('insert into test_autocommit(field) values(1)')
        assert 0 == conn._trancount()


def test_bulk_insert(cursor):
    cur = cursor
    f = StringIO("42\tfoo\n74\tbar\n")
    cur.copy_to(f, 'bulk_insert_table', schema='myschema', columns=('num', 'data'))
    cur.execute('select num, data from myschema.bulk_insert_table')
    assert [(42, 'foo'), (74, 'bar')] == cur.fetchall()


def test_bug2(cursor):
    cur = cursor
    cur.execute('''
    create procedure testproc_bug2 (@param int)
    as
    begin
        set transaction isolation level read uncommitted -- that will produce very empty result (even no rowcount)
        select @param
        return @param + 1
    end
    ''')
    val = 45
    cur.execute('exec testproc_bug2 @param = 45')
    assert cur.fetchall() == [(val,)]
    assert val + 1 == cur.get_proc_return_status()


def test_stored_proc(cursor):
    cur = cursor
    val = 45
    #params = {'@param': val, '@outparam': output(None), '@add': 1}
    values = cur.callproc('testproc', (val, pytds.default, pytds.output(value=1)))
    #self.assertEqual(cur.fetchall(), [(val,)])
    assert val + 2 == values[2]
    assert val + 2 == cur.get_proc_return_status()


def test_table_selects(db_connection):
    cur = db_connection.cursor()
    cur.execute(u'''
    create table #testtable (id int, _text text, _xml xml, vcm varchar(max), vc varchar(10))
    ''')
    cur.execute(u'''
    insert into #testtable (id, _text, _xml, vcm, vc) values (1, 'text', '<root/>', '', NULL)
    ''')
    cur.execute('select id from #testtable order by id')
    assert [(1,)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute('select _text from #testtable order by id')
    assert [(u'text',)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute('select _xml from #testtable order by id')
    assert [('<root/>',)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute('select id, _text, _xml, vcm, vc from #testtable order by id')
    assert (1, 'text', '<root/>', '', None) == cur.fetchone()

    cur = db_connection.cursor()
    cur.execute('select vc from #testtable order by id')
    assert [(None,)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute('insert into #testtable (_xml) values (%s)', ('<some/>',))

    cur = db_connection.cursor()
    cur.execute(u'drop table #testtable')


def test_decimals(cursor):
    cur = cursor
    assert Decimal(12) == cur.execute_scalar('select cast(12 as decimal) as fieldname')
    assert Decimal(-12) == cur.execute_scalar('select cast(-12 as decimal) as fieldname')
    assert Decimal('123456.12345') == cur.execute_scalar("select cast('123456.12345'as decimal(20,5)) as fieldname")
    assert Decimal('-123456.12345') == cur.execute_scalar("select cast('-123456.12345'as decimal(20,5)) as fieldname")


def test_bulk_insert_with_special_chars_no_columns(cursor):
    cur = cursor
    cur.execute('create table [test]] table](num int not null, data varchar(100))')
    f = StringIO("42\tfoo\n74\tbar\n")
    cur.copy_to(f, 'test] table')
    cur.execute('select num, data from [test]] table]')
    assert cur.fetchall() == [(42, 'foo'), (74, 'bar')]


def test_bulk_insert_with_special_chars(cursor):
    cur = cursor
    cur.execute('create table [test]] table](num int, data varchar(100))')
    f = StringIO("42\tfoo\n74\tbar\n")
    cur.copy_to(f, 'test] table', columns=('num', 'data'))
    cur.execute('select num, data from [test]] table]')
    assert cur.fetchall() == [(42, 'foo'), (74, 'bar')]


def test_table_valued_type_autodetect(separate_db_connection):
    def rows_gen():
        yield (1, 'test1')
        yield (2, 'test2')

    with separate_db_connection.cursor() as cur:
        cur.execute('CREATE TYPE dbo.CategoryTableType AS TABLE ( CategoryID int, CategoryName nvarchar(50) )')
        separate_db_connection.commit()

        tvp = pytds.TableValuedParam(type_name='dbo.CategoryTableType', rows=rows_gen())
        cur.execute('SELECT * FROM %s', (tvp,))
        assert cur.fetchall() == [(1, 'test1'), (2, 'test2')]

        cur.execute('DROP TYPE dbo.CategoryTableType')
        separate_db_connection.commit()


def test_table_valued_type_explicit(separate_db_connection):
    def rows_gen():
        yield (1, 'test1')
        yield (2, 'test2')

    with separate_db_connection.cursor() as cur:
        cur.execute('CREATE TYPE dbo.CategoryTableType AS TABLE ( CategoryID int, CategoryName nvarchar(50) )')
        separate_db_connection.commit()

        tvp = pytds.TableValuedParam(
            type_name='dbo.CategoryTableType',
            columns=(pytds.Column(type=pytds.tds_types.IntType()), pytds.Column(type=pytds.tds_types.NVarCharType(size=30))),
            rows=rows_gen())
        cur.execute('SELECT * FROM %s', (tvp,))
        assert cur.fetchall() == [(1, 'test1'), (2, 'test2')]

        cur.execute('DROP TYPE dbo.CategoryTableType')
        separate_db_connection.commit()


def test_reading_values(cursor):
    cur = cursor
    with pytest.raises(pytds.ProgrammingError):
        cur.execute(u'select ')
    assert 'abc' == cur.execute_scalar("select cast('abc' as varchar(max)) as fieldname")
    assert 'abc' == cur.execute_scalar("select cast('abc' as nvarchar(max)) as fieldname")
    assert b'abc' == cur.execute_scalar("select cast('abc' as varbinary(max)) as fieldname")
    #assert 12 == cur.execute_scalar('select cast(12 as bigint) as fieldname')
    assert 12 == cur.execute_scalar('select cast(12 as smallint) as fieldname')
    assert -12 == cur.execute_scalar('select -12 as fieldname')
    assert 12 == cur.execute_scalar('select cast(12 as tinyint) as fieldname')
    assert True == cur.execute_scalar('select cast(1 as bit) as fieldname')
    assert 5.1 == cur.execute_scalar('select cast(5.1 as float) as fieldname')
    cur.execute("select 'test', 20")
    assert ('test', 20) == cur.fetchone()
    assert 'test' == cur.execute_scalar("select 'test' as fieldname")
    assert 'test' == cur.execute_scalar("select N'test' as fieldname")
    assert 'test' == cur.execute_scalar("select cast(N'test' as ntext) as fieldname")
    assert 'test' == cur.execute_scalar("select cast(N'test' as text) as fieldname")
    assert 'test ' == cur.execute_scalar("select cast(N'test' as char(5)) as fieldname")
    assert 'test ' == cur.execute_scalar("select cast(N'test' as nchar(5)) as fieldname")
    assert b'test' == cur.execute_scalar("select cast('test' as varbinary(4)) as fieldname")
    assert b'test' == cur.execute_scalar("select cast('test' as image) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as image) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as varbinary(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as ntext) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as nvarchar(max)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as xml)")
    assert None is cur.execute_scalar("select cast(NULL as varchar(max)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as nvarchar(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as varchar(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as nchar(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
    assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
    assert 5 == cur.execute_scalar('select 5 as fieldname')
    with pytest.raises(pytds.ProgrammingError) as ex:
        cur.execute_scalar('create table exec_scalar_empty(f int)')
    # message does not have to be exact match
    assert "Previous statement didn't produce any results" in str(ex.value)


def test_money(cursor):
    cur = cursor
    assert Decimal('0') == cur.execute_scalar("select cast('0' as money) as fieldname")
    assert Decimal('1') == cur.execute_scalar("select cast('1' as money) as fieldname")
    assert Decimal('1.5555') == cur.execute_scalar("select cast('1.5555' as money) as fieldname")
    assert Decimal('1234567.5555') == cur.execute_scalar("select cast('1234567.5555' as money) as fieldname")
    assert Decimal('-1234567.5555') == cur.execute_scalar("select cast('-1234567.5555' as money) as fieldname")
    assert Decimal('12345.55') == cur.execute_scalar("select cast('12345.55' as smallmoney) as fieldname")


def test_strs(cursor):
    cur = cursor
    assert isinstance(cur.execute_scalar("select 'test'"), six.text_type)
