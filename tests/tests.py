# vim: set fileencoding=utf8 :
from __future__ import with_statement
import unittest
import sys
from decimal import Decimal, getcontext
import logging
from datetime import datetime, date, time
import uuid
from dateutil.tz import tzoffset, tzutc
from six import text_type
from six.moves import xrange
from pytds import (connect, ProgrammingError, TimeoutError, Time, SimpleLoadBalancer, LoginError,
    Error, IntegrityError, Timestamp, DataError, DECIMAL, Date, Binary, DateTime,
    IS_TDS73_PLUS, IS_TDS71_PLUS,
    output, default, InterfaceError)
from pytds.tds import _TdsSocket, _TdsSession
import pytds.tds

# set decimal precision to match mssql maximum precision
getcontext().prec = 38

try:
    from . import settings
except:
    print('Settings module is not found, please create settings module and specify HOST, DATATABSE, USER and PASSWORD there')
    sys.exit(1)

#logging.basicConfig(level='DEBUG')
#logging.basicConfig(level='INFO')
logging.basicConfig()

class TestCase(unittest.TestCase):
    def setUp(self):
        self.conn = connect(*settings.CONNECT_ARGS, **settings.CONNECT_KWARGS)
    def tearDown(self):
        self.conn.close()


class DbTestCase(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        del kwargs['database']
        self.conn = connect(**kwargs)
        with self.conn.cursor() as cur:
            self.conn.autocommit = True
            try:
                cur.execute('drop database test_pytds')
            except:
                pass
            cur.execute('create database test_pytds')
            cur.execute('use test_pytds')
            self.conn.autocommit = False

    def tearDown(self):
        #with self.conn.cursor() as cur:
        #    self.conn.rollback()
        #    self.conn.autocommit = True
        #    cur.execute('drop database test_pytds')
        self.conn.close()


class TestCase2(TestCase):
    def test_all(self):
        cur = self.conn.cursor()
        with self.assertRaises(ProgrammingError):
            cur.execute(u'select ')
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
        self.assertEqual('test ', cur.execute_scalar("select cast(N'test' as char(5)) as fieldname"))
        self.assertEqual('test ', cur.execute_scalar("select cast(N'test' as nchar(5)) as fieldname"))
        assert b'test' == cur.execute_scalar("select cast('test' as varbinary(4)) as fieldname")
        assert b'test' == cur.execute_scalar("select cast('test' as image) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as image) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as varbinary(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as ntext) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as nvarchar(max)) as fieldname")
        self.assertEqual(None, cur.execute_scalar("select cast(NULL as varchar(max)) as fieldname"))
        assert None == cur.execute_scalar("select cast(NULL as nvarchar(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as varchar(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as nchar(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
        self.assertEqual(u'Iñtërnâtiônàlizætiøn1', cur.execute_scalar('select %s', (u'Iñtërnâtiônàlizætiøn1'.encode('utf8'),)))
        assert 5 == cur.execute_scalar('select 5 as fieldname')

    def test_decimals(self):
        cur = self.conn.cursor()
        assert Decimal(12) == cur.execute_scalar('select cast(12 as decimal) as fieldname')
        assert Decimal(-12) == cur.execute_scalar('select cast(-12 as decimal) as fieldname')
        assert Decimal('123456.12345') == cur.execute_scalar("select cast('123456.12345'as decimal(20,5)) as fieldname")
        assert Decimal('-123456.12345') == cur.execute_scalar("select cast('-123456.12345'as decimal(20,5)) as fieldname")

    def test_money(self):
        cur = self.conn.cursor()
        assert Decimal('0') == cur.execute_scalar("select cast('0' as money) as fieldname")
        assert Decimal('1') == cur.execute_scalar("select cast('1' as money) as fieldname")
        self.assertEqual(Decimal('1.5555'), cur.execute_scalar("select cast('1.5555' as money) as fieldname"))
        assert Decimal('1234567.5555') == cur.execute_scalar("select cast('1234567.5555' as money) as fieldname")
        assert Decimal('-1234567.5555') == cur.execute_scalar("select cast('-1234567.5555' as money) as fieldname")
        assert Decimal('12345.55') == cur.execute_scalar("select cast('12345.55' as smallmoney) as fieldname")

    def test_timeout(self):
        with connect(login_timeout=1, *settings.CONNECT_ARGS, **settings.CONNECT_KWARGS) as conn:
            cur = conn.cursor()
            with self.assertRaises(TimeoutError):
                cur.execute("waitfor delay '00:00:05'")
            cur.execute('select 1')

    def test_strs(self):
        cur = self.conn.cursor()
        self.assertIsInstance(cur.execute_scalar("select 'test'"), text_type)

    #def test_mars_sessions_recycle_ids(self):
    #    if not self.conn.mars_enabled:
    #        self.skipTest('Only relevant to mars')
    #    for _ in xrange(2 ** 16 + 1):
    #        cur = self.conn.cursor()
    #        cur.close()

    def test_smp(self):
        if not self.conn.mars_enabled:
            self.skipTest('Only relevant to mars')
        sess = self.conn._conn._smp_manager.create_session()
        self.assertEqual(sess._state, 'SESSION ESTABLISHED')
        sess.close()
        self.assertEqual(sess._state, 'CLOSED')


class DbTests(DbTestCase):
    def test_autocommit(self):
        self.assertFalse(self.conn.autocommit)
        with self.conn.cursor() as cur:
            cur.execute('create table test_autocommit(field int)')
            self.conn.commit()
            self.assertEqual(self.conn._trancount(), 1)
            cur.execute('insert into test_autocommit(field) values(1)')
            self.assertEqual(self.conn._trancount(), 1)
            cur.execute('select field from test_autocommit')
            row = cur.fetchone()
            self.conn.rollback()
            cur.execute('select field from test_autocommit')
            row = cur.fetchone()
            self.assertFalse(row)

            self.conn.autocommit = True
            cur.execute('insert into test_autocommit(field) values(1)')
            self.assertEqual(self.conn._trancount(), 0)


class ParametrizedQueriesTestCase(TestCase):
    def _test_val(self, val):
        cur = self.conn.cursor()
        cur.execute('select %s', (val,))
        self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        self._test_val(u'hello')
        self._test_val(123)
        self._test_val(-123)
        self._test_val(123.12)
        self._test_val(-123.12)
        self._test_val(datetime(2011, 2, 3, 10, 11, 12, 3000))
        self._test_val(Decimal('1234.567'))
        self._test_val(Decimal('1234000'))
        self._test_val(None)
        self._test_val('hello')
        self._test_val('')
        self._test_val('x' * 5000)
        self._test_val(Binary(b'x' * 5000))
        self._test_val(2**63 - 1)
        self._test_val(False)
        self._test_val(True)

class TableTestCase(DbTestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute(u'''
        create table #testtable (id int, _text text, _xml xml, vcm varchar(max), vc varchar(10))
        ''')
        cur.execute(u'''
        insert into #testtable (id, _text, _xml, vcm, vc) values (1, 'text', '<root/>', '', NULL)
        ''')
        cur.execute('select id from #testtable order by id')
        self.assertEqual([(1,)], cur.fetchall())

        cur = self.conn.cursor()
        cur.execute('select _text from #testtable order by id')
        self.assertEqual([(u'text',)], cur.fetchall())

        cur = self.conn.cursor()
        cur.execute('select _xml from #testtable order by id')
        self.assertEqual([('<root/>',)], cur.fetchall())

        cur = self.conn.cursor()
        cur.execute('select id, _text, _xml, vcm, vc from #testtable order by id')
        self.assertTupleEqual((1, 'text', '<root/>', '', None), cur.fetchone())

        cur = self.conn.cursor()
        cur.execute('select vc from #testtable order by id')
        self.assertEqual([(None,)], cur.fetchall())

        cur = self.conn.cursor()
        cur.execute('insert into #testtable (_xml) values (%s)', ('<some/>',))

    def tearDown(self):
        cur = self.conn.cursor()
        cur.execute(u'drop table #testtable')
        super(TableTestCase, self).tearDown()


class StoredProcsTestCase(DbTestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('''
        create procedure testproc (@param int, @add int = 2, @outparam int output)
        as
        begin
            set nocount on
            --select @param
            set @outparam = @param + @add
            return @outparam
        end
        ''')
        val = 45
        #params = {'@param': val, '@outparam': output(None), '@add': 1}
        values = cur.callproc('testproc', (val, default, output(None, 1)))
        #self.assertEqual(cur.fetchall(), [(val,)])
        self.assertEqual(val + 2, values[2])
        self.assertEqual(val + 2, cur.get_proc_return_status())


class CursorCloseTestCase(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('select 10; select 12')
            cur.fetchone()
        with self.conn.cursor() as cur2:
            cur2.execute('select 20')
            cur2.fetchone()


class MultipleRecordsetsTestCase(TestCase):
    def test_fetchone(self):
        with self.conn.cursor() as cur:
            cur.execute('select 10; select 12')
            self.assertEqual((10,), cur.fetchone())
            self.assertTrue(cur.nextset())
            self.assertEqual((12,), cur.fetchone())
            self.assertFalse(cur.nextset())

    def test_fetchall(self):
        with self.conn.cursor() as cur:
            cur.execute('select 10; select 12')
            self.assertEqual([(10,)], cur.fetchall())
            self.assertTrue(cur.nextset())
            self.assertEqual([(12,)], cur.fetchall())
            self.assertFalse(cur.nextset())


class TransactionsTestCase(DbTestCase):
    def runTest(self):
        self.conn.autocommit = False
        with self.conn.cursor() as cur:
            cur.execute('''
            create table testtable (field datetime)
            ''')
            cur.execute("select object_id('testtable')")
            self.assertNotEqual((None,), cur.fetchone())

            self.assertEqual(1, self.conn._trancount())

            self.conn.rollback()

            self.assertEqual(1, self.conn._trancount())

            cur.execute("select object_id('testtable')")
            self.assertEqual((None,), cur.fetchone())

            cur.execute('''
            create table testtable (field datetime)
            ''')

            self.conn.commit()

            cur.execute("select object_id('testtable')")
            self.assertNotEqual((None,), cur.fetchone())

    def tearDown(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
        self.conn.commit()
        super(TransactionsTestCase, self).tearDown()

class MultiPacketRequest(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        param = 'x' * (self.conn._conn.main_session._writer.bufsize*3)
        cur.execute('select %s', (param,))
        self.assertEqual([(param, )], cur.fetchall())

class BigRequest(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            param = 'x' * 5000
            params = (10, datetime(2012, 11, 19, 1, 21, 37, 3000), param, 'test')
            cur.execute('select %s, %s, %s, %s', params)
            self.assertEqual([params], cur.fetchall())

class ReadAllBug(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        params = ('x' * 5000,)
        cur.execute('select cast(%s as varchar(5000))', params)
        self.assertEqual([params], cur.fetchall())

class Rowcount(DbTestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('''
        create table testtable (field int)
        ''')
        cur.execute('insert into testtable (field) values (1)')
        self.assertEqual(cur.rowcount, 1)
        cur.execute('insert into testtable (field) values (2)')
        self.assertEqual(cur.rowcount, 1)
        cur.execute('select * from testtable')
        cur.fetchall()
        #self.assertEqual(cur.rowcount, 2)

class NoRows(DbTestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('''
        create table testtable (field int)
        ''')
        cur.execute('select * from testtable')
        self.assertEqual([], cur.fetchall())


class TestVariant(TestCase):
    def _t(self, result, sql):
        with self.conn.cursor() as cur:
            cur.execute("select cast({} as sql_variant)".format(sql))
            val, = cur.fetchone()
            self.assertEqual(result, val)

    def test_new_datetime(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        self._t(datetime(2011, 2, 3, 10, 11, 12, 3000), "cast('2011-02-03T10:11:12.003000' as datetime2)")
        self._t(time(10, 11, 12, 3000), "cast('10:11:12.003000' as time)")
        self._t(date(2011, 2, 3), "cast('2011-02-03' as date)")
        self._t(datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset('', 3*60*60)), "cast('2011-02-03T10:11:12.003000+03:00' as datetimeoffset)")

    def test_regular(self):
        if not IS_TDS71_PLUS(self.conn):
            self.skipTest('Requires TDS7.1+')
        self._t(None, "cast(NULL as varchar)")
        self._t('test', "cast('test' as varchar)")
        self._t('test ', "cast('test' as char(5))")
        self._t('test', "cast(N'test' as nvarchar)")
        self._t('test ', "cast(N'test' as nchar(5))")
        self._t(Decimal('100.55555'), "cast(100.55555 as decimal(8,5))")
        self._t(Decimal('100.55555'), "cast(100.55555 as numeric(8,5))")
        self._t(b'test', "cast('test' as varbinary)")
        self._t(b'test\x00', "cast('test' as binary(5))")
        self._t(datetime(2011, 2, 3, 10, 11, 12, 3000), "cast('2011-02-03T10:11:12.003' as datetime)")
        self._t(datetime(2011, 2, 3, 10, 11, 0), "cast('2011-02-03T10:11:00' as smalldatetime)")
        val = uuid.uuid4()
        self._t(val, "cast('{}' as uniqueidentifier)".format(val))
        self._t(True, "cast(1 as bit)")
        self._t(128, "cast(128 as tinyint)")
        self._t(-32000, "cast(-32000 as smallint)")
        self._t(2000000000, "cast(2000000000 as int)")
        self._t(2000000000000, "cast(2000000000000 as bigint)")
        self._t(0.12345, "cast(0.12345 as float)")
        self._t(0.25, "cast(0.25 as real)")
        self._t(Decimal('922337203685477.5807'), "cast('922,337,203,685,477.5807' as money)")
        self._t(Decimal('-214748.3648'), "cast('- 214,748.3648' as smallmoney)")

class BadConnection(unittest.TestCase):
    def runTest(self):
        with self.assertRaises(Error):
            with connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD+'bad') as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
        with self.assertRaises(Error):
            with connect(server=settings.HOST+'bad', database=settings.DATABASE, user=settings.USER+'bad', password=settings.PASSWORD) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
        with self.assertRaises(Error):
            with connect(server=settings.HOST, database=settings.DATABASE+'x', user=settings.USER, password=settings.PASSWORD) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
        with self.assertRaises(Error):
            with connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=None) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')

class NullXml(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        cur.execute('select cast(NULL as xml)')
        self.assertEqual([(None,)], cur.fetchall())
        cur.execute('select cast(%s as xml)', (None,))
        self.assertEqual([(None,)], cur.fetchall())


def get_spid(conn):
    with conn.cursor() as cur:
        return cur.spid


def kill(conn, spid):
    with conn.cursor() as cur:
        cur.execute('kill {}'.format(spid))


class ConnectionClosing(unittest.TestCase):
    def test_open_close(self):
        for x in xrange(3):
            connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD).close()

    def test_connection_closed_by_server(self):
        with connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD, autocommit=True) as master_conn:
            with connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD) as conn:
                # test overall recovery
                kill(master_conn, get_spid(conn))
                with conn.cursor() as cur:
                    with self.assertRaises(Exception):
                        cur.execute('select 1')
                    cur.execute('select 1')
                    cur.fetchall()
            #with connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD) as conn:
            #    spid = get_spid(conn)
            #    with conn.cursor() as cur:
            #        # test recovery of specific lowlevel methods
            #        tds_submit_query(cur._session, "waitfor delay '00:00:05'; select 1")
            #        kill(master_conn, spid)
            #        self.assertTrue(cur._session.is_connected())
            #        with self.assertRaises(Exception):
            #            tds_process_tokens(cur._session, TDS_TOKEN_RESULTS)
            #        self.assertFalse(cur._session.is_connected())


class Description(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('select cast(12.65 as decimal(4,2)) as testname')
            self.assertEqual(cur.description[0][0], 'testname')
            self.assertEqual(cur.description[0][1], DECIMAL)
            self.assertEqual(cur.description[0][4], 4)
            self.assertEqual(cur.description[0][5], 2)

class Bug1(TestCase):
    def runTest(self):
        try:
            with connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD+'bad') as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
                    cur.fetchall()
                conn.rollback()
        except:
            pass

class BinaryTest(TestCase):
    def runTest(self):
        binary = b'\x00\x01\x02'
        with self.conn.cursor() as cur:
            cur.execute('select %s', (Binary(binary),))
            self.assertEqual([(binary,)], cur.fetchall())


class GuidTest(TestCase):
    def runTest(self):
        cur = self.conn.cursor()
        val = uuid.uuid4()
        cur.execute('select %s', (val,))
        self.assertEqual([(val,)], cur.fetchall())


#class EncryptionTest(unittest.TestCase):
#    def runTest(self):
#        conn = connect(server=settings.HOST, database=settings.DATABASE, user=settings.USER, password=settings.PASSWORD, encryption_level=TDS_ENCRYPTION_REQUIRE)
#        cur = conn.cursor()
#        cur.execute('select 1')

class Bug2(DbTestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            create procedure testproc (@param int)
            as
            begin
                set transaction isolation level read uncommitted -- that will produce very empty result (even no rowcount)
                select @param
                return @param + 1
            end
            ''')
            val = 45
            cur.execute('exec testproc @param = 45')
            self.assertEqual(cur.fetchall(), [(val,)])
            self.assertEqual(val + 1, cur.get_proc_return_status())

class Bug3(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.close()

class DateAndTimeParams(TestCase):
    def test_date(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        with self.conn.cursor() as cur:
            date = Date(2012, 10, 6)
            cur.execute('select %s', (date, ))
            self.assertEqual(cur.fetchall(), [(date,)])

    def test_time(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        with self.conn.cursor() as cur:
            time = Time(8, 7, 4, 123000)
            cur.execute('select %s', (time, ))
            self.assertEqual(cur.fetchall(), [(time,)])

    def test_datetime(self):
        with self.conn.cursor() as cur:
            time = Timestamp(2013, 7, 9, 8, 7, 4, 123000)
            cur.execute('select %s', (time, ))
            self.assertEqual(cur.fetchall(), [(time,)])

class Bug4(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            set transaction isolation level read committed
            select 1
            ''')
            self.assertEqual(cur.fetchall(), [(1,)])

class FixedSizeChar(DbTestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            create table testtable (chr char(5), nchr nchar(5), bfld binary(5))
            insert into testtable values ('1', '2', cast('3' as binary(5)))
            ''')
            cur.execute('select * from testtable')
            self.assertEqual(cur.fetchall(), [('1    ', '2    ', b'3\x00\x00\x00\x00')])

class EdgeCases(TestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select %s', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        with self.conn.cursor() as cur:
            self._testval(10**20)
            self._testval(10**38-1)
            self._testval(-10**38+1)
            with self.assertRaises(DataError):
                self._testval(-10**38)
            ##cur.execute('select %s', '\x00'*(2**31))
            self._testval(Decimal('9'*38))
            self._testval(Decimal('0.'+'9'*38))
            self._testval(-Decimal('9'*38))
            self._testval(Decimal('1E10'))
            self._testval(Decimal('1E-10'))
            self._testval(Decimal('0.{0}1'.format('0'*37)))
            with self.assertRaises(DataError):
                self._testval(Decimal('1' + '0'*38))
            with self.assertRaises(DataError):
                self._testval(Decimal('-1' + '0'*38))
            with self.assertRaises(DataError):
                self._testval(Decimal('1E38'))

class Extensions(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            self.assertEqual(cur.connection, self.conn)

class SmallDateTimeTest(TestCase):
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as smalldatetime)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        self._testval(Timestamp(2010, 2, 1, 10, 12, 0))
        self._testval(Timestamp(1900, 1, 1, 0, 0, 0))
        self._testval(Timestamp(2079, 6, 6, 23, 59, 0))
        with self.assertRaises(Error):
            self._testval(Timestamp(1899, 1, 1, 0, 0, 0))
        with self.assertRaises(Error):
            self._testval(Timestamp(2080, 1, 1, 0, 0, 0))

class DateTimeTest(DbTestCase):
    def _testencdec(self, val):
        self.assertEqual(val, DateTime.decode(*DateTime._struct.unpack(DateTime.encode(val))))
    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as datetime)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])
    def runTest(self):
        self.assertEqual(DateTime.decode(*DateTime._struct.unpack(b'\xf2\x9c\x00\x00}uO\x01')), Timestamp(2010, 1, 2, 20, 21, 22, 123000))
        self.assertEqual(DateTime.decode(*DateTime._struct.unpack(b'\x7f$-\x00\xff\x81\x8b\x01')), DateTime._max_date)
        self.assertEqual(b'\xf2\x9c\x00\x00}uO\x01', DateTime.encode(Timestamp(2010, 1, 2, 20, 21, 22, 123000)))
        self.assertEqual(b'\x7f$-\x00\xff\x81\x8b\x01', DateTime.encode(DateTime._max_date))
        with self.conn.cursor() as cur:
            cur.execute("select cast('9999-12-31T23:59:59.997' as datetime)")
            self.assertEqual(cur.fetchall(), [(Timestamp(9999, 12, 31, 23, 59, 59, 997000),)])
        self._testencdec(Timestamp(2010, 1, 2, 10, 11, 12))
        self._testval(Timestamp(2010, 1, 2, 0, 0, 0))
        self._testval(Timestamp(2010, 1, 2, 10, 11, 12))
        self._testval(Timestamp(1753, 1, 1, 0, 0, 0))
        self._testval(Timestamp(9999, 12, 31, 0, 0, 0))
        with self.conn.cursor() as cur:
            cur.execute("select cast(null as datetime)")
            self.assertEqual(cur.fetchall(), [(None,)])
        self._testval(Timestamp(9999, 12, 31, 23, 59, 59, 997000))
        with self.assertRaises(Error):
            self._testval(Timestamp(1752, 1, 1, 0, 0, 0))
        with self.conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
            cur.execute('create table testtable (col datetime not null)')
            dt = Timestamp(2010, 1, 2, 20, 21, 22, 123000)
            cur.execute('insert into testtable values (%s)', (dt,))
            cur.execute('select col from testtable')
            self.assertEqual(cur.fetchone(), (dt,))


class NewDateTimeTest(TestCase):
    def test_datetimeoffset(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        def _testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as datetimeoffset)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])
        with self.conn.cursor() as cur:
            cur.execute("select cast('2010-01-02T20:21:22.1234567+05:00' as datetimeoffset)")
            self.assertEqual(datetime(2010, 1, 2, 20, 21, 22, 123456, tzoffset('', 5*60*60)), cur.fetchone()[0])
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzutc()))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', 5*60*60)))
        _testval(Timestamp(1, 1, 1, 0, 0, 0, 0, tzutc()))
        _testval(Timestamp(9999, 12, 31, 23, 59, 59, 999999, tzutc()))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', 14*60)))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', -14*60)))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset('', -15*60)))

    def test_time(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        def testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as time)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])
        testval(Time(14,16,18,123456))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))
        testval(Time(23, 59, 59, 999999))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))
        testval(Time(0, 0, 0, 0))

    def test_datetime2(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        def testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as datetime2)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])
        testval(Timestamp(2010, 1, 2, 20, 21, 22, 345678))
        testval(Timestamp(2010, 1, 2, 0, 0, 0))
        testval(Timestamp(1, 1, 1, 0, 0, 0))
        testval(Timestamp(9999, 12, 31, 23, 59, 59, 999999))

    def test_date(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        def testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as date)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])
        testval(Date(2010, 1, 2))
        testval(Date(2010, 1, 2))
        testval(Date(1, 1, 1))
        testval(Date(9999, 12, 31))


class Auth(unittest.TestCase):
    #def test_ntlm(self):
    #    conn = connect(settings.HOST, auth=NtlmAuth(user_name=settings.NTLM_USER, password=settings.NTLM_PASSWORD))
    #    with conn.cursor() as cursor:
    #        cursor.execute('select 1')
    #        cursor.fetchall()

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sspi(self):
        from pytds.login import SspiAuth
        with connect(settings.HOST, auth=SspiAuth()) as conn:
            with conn.cursor() as cursor:
                cursor.execute('select 1')
                cursor.fetchall()

    def test_sqlauth(self):
        with connect(settings.HOST, user=settings.USER, password=settings.PASSWORD) as conn:
            with conn.cursor() as cursor:
                cursor.execute('select 1')
                cursor.fetchall()


class CloseCursorTwice(TestCase):
    def runTest(self):
        cursor = self.conn.cursor()
        cursor.close()
        cursor.close()


class RegressionSuite(TestCase):
    def test_commit(self):
        if self.conn.mars_enabled:
            self.skipTest('Only breaks when mars is disabled')
        cursor = self.conn.cursor()
        cursor.execute('select 1')
        cursor.fetchall()
        self.conn.commit()


class TestLoadBalancer(TestCase):
    def test_second(self):
        lb = SimpleLoadBalancer(['badserver', settings.CONNECT_KWARGS['server']])
        with connect(load_balancer=lb, *settings.CONNECT_ARGS, **settings.CONNECT_KWARGS) as conn:
            with conn.cursor() as cur:
                cur.execute('select 1')
                cur.fetchall()

    def test_none(self):
        lb = SimpleLoadBalancer(['badserver'])
        with self.assertRaises(LoginError):
            with connect(load_balancer=lb, *settings.CONNECT_ARGS, **settings.CONNECT_KWARGS) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
                    cur.fetchall()


class TestIntegrityError(DbTestCase):
    def test_primary_key(self):
        cursor = self.conn.cursor()
        cursor.execute('create table testtable(pk int primary key)')
        cursor.execute('insert into testtable values (1)')
        with self.assertRaises(IntegrityError):
            cursor.execute('insert into testtable values (1)')


class TimezoneTests(unittest.TestCase):
    def check_val(self, conn, sql, input, output):
        with conn.cursor() as cur:
            cur.execute('select ' + sql, (input,))
            rows = cur.fetchall()
            self.assertEqual(rows[0][0], output)

    def runTest(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        use_tz = tzutc()
        kwargs['use_tz'] = use_tz
        with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
            # Naive time should be interpreted as use_tz
            self.check_val(conn, '%s',
                           datetime(2011, 2, 3, 10, 11, 12, 3000),
                           datetime(2011, 2, 3, 10, 11, 12, 3000, tzutc()))
            # Aware time shoule be passed as-is
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset('', 60))
            self.check_val(conn, '%s', dt, dt)
            # Aware time should be converted to use_tz if not using datetimeoffset type
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset('', 60))
            if IS_TDS73_PLUS(conn):
                self.check_val(conn, 'cast(%s as datetime2)', dt, dt.astimezone(use_tz))


class _FakeSock(object):
    def __init__(self, messages):
        self._stream = b''.join(messages)

    def recv(self, size):
        if not self._stream:
            return b''
        res = self._stream[:size]
        self._stream = self._stream[size:]
        return res

    def send(self, buf, flags):
        self._sent = buf
        return len(buf)

    def setsockopt(self, *args):
        pass

    def close(self):
        self._stream = b''


class TestMessages(unittest.TestCase):
    def _make_login(self):
        from pytds.dbapi import _TdsLogin
        from pytds.tds import TDS74
        login = _TdsLogin()
        login.blocksize = 4096
        login.use_tz = None
        login.query_timeout = login.connect_timeout = 60
        login.tds_version = TDS74
        login.instance_name = None
        login.encryption_level = None
        login.use_mars = False
        login.option_flag2 = 0
        login.user_name = 'testname'
        login.password = 'password'
        login.app_name = 'appname'
        login.server_name = 'servername'
        login.library = 'library'
        login.language = 'EN'
        login.database = 'database'
        login.auth = None
        login.bulk_copy = False
        login.readonly = False
        login.client_lcid = 100
        login.attach_db_file = ''
        login.text_size = 0
        return login

    def test_login(self):
        sock = _FakeSock([
            b'\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\xff\n\x00\x15\x88\x00\x00\x02\x00\x00',
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00\x06m\x00a\x00s\x00t\x00e\x00r\x00\xab~\x00E\x16\x00\x00\x02\x00/\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00d\x00a\x00t\x00a\x00b\x00a\x00s\x00e\x00 \x00c\x00o\x00n\x00t\x00e\x00x\x00t\x00 \x00t\x00o\x00 \x00'\x00S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00'\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xe3\x08\x00\x07\x05\t\x04\x00\x01\x00\x00\xe3\x17\x00\x02\nu\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00\x00\xabn\x00G\x16\x00\x00\x01\x00'\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00l\x00a\x00n\x00g\x00u\x00a\x00g\x00e\x00 \x00s\x00e\x00t\x00t\x00i\x00n\x00g\x00 \x00t\x00o\x00 \x00u\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xad6\x00\x01s\x0b\x00\x03\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\n\x00\x15\x88\xe3\x13\x00\x04\x044\x000\x009\x006\x00\x044\x000\x009\x006\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b'\x04\x01\x00#\x00Z\x01\x00\xe3\x0b\x00\x08\x08\x01\x00\x00\x00Z\x00\x00\x00\x00\xfd\x00\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            ])
        _TdsSocket().login(self._make_login(), sock)

        # test connection close on first message
        sock = _FakeSock([
            b'\x04\x01\x00+\x00',
            ])
        with self.assertRaises(Error):
            _TdsSocket().login(self._make_login(), sock)

        # test connection close on second message
        sock = _FakeSock([
            b'\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\xff\n\x00\x15\x88\x00\x00\x02\x00\x00',
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S",
            ])
        with self.assertRaises(Error):
            _TdsSocket().login(self._make_login(), sock)

        # test connection close on third message
        sock = _FakeSock([
            b'\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\xff\n\x00\x15\x88\x00\x00\x02\x00\x00',
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00\x06m\x00a\x00s\x00t\x00e\x00r\x00\xab~\x00E\x16\x00\x00\x02\x00/\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00d\x00a\x00t\x00a\x00b\x00a\x00s\x00e\x00 \x00c\x00o\x00n\x00t\x00e\x00x\x00t\x00 \x00t\x00o\x00 \x00'\x00S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00'\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xe3\x08\x00\x07\x05\t\x04\x00\x01\x00\x00\xe3\x17\x00\x02\nu\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00\x00\xabn\x00G\x16\x00\x00\x01\x00'\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00l\x00a\x00n\x00g\x00u\x00a\x00g\x00e\x00 \x00s\x00e\x00t\x00t\x00i\x00n\x00g\x00 \x00t\x00o\x00 \x00u\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xad6\x00\x01s\x0b\x00\x03\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\n\x00\x15\x88\xe3\x13\x00\x04\x044\x000\x009\x006\x00\x044\x000\x009\x006\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b'\x04\x01\x00#\x00Z\x01\x00\xe3\x0b\x00\x08\x08\x01\x00\x00\x00Z\x00\x00\x00\x00\xfd\x00\x00\xfd\x00\x00',
            ])
        with self.assertRaises(Error):
            _TdsSocket().login(self._make_login(), sock)

    def test_prelogin_resp(self):
        # test bad packet type
        sock = _FakeSock([
            b'\x03\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\xff\n\x00\x15\x88\x00\x00\x02\x00\x00',
            ])
        tds = _TdsSocket()
        tds._main_session = _TdsSession(tds, tds)
        tds._sock = sock
        with self.assertRaises(InterfaceError):
            tds._main_session.tds71_do_login(self._make_login())

        # test bad offset 1
        sock = _FakeSock([
            b'\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\x00\n\x00\x15\x88\x00\x00\x02\x00\x00',
            ])
        tds = _TdsSocket()
        tds._main_session = _TdsSession(tds, tds)
        tds._sock = sock
        with self.assertRaises(InterfaceError):
            tds._main_session.tds71_do_login(self._make_login())

        # test bad offset 2
        sock = _FakeSock([
            b'\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00',
            ])
        tds = _TdsSocket()
        tds._main_session = _TdsSession(tds, tds)
        tds._sock = sock
        with self.assertRaises(InterfaceError):
            tds._main_session.tds71_do_login(self._make_login())

    def test_process_login(self):
        sock = _FakeSock([
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00\x06m\x00a\x00s\x00t\x00e\x00r\x00\xab~\x00E\x16\x00\x00\x02\x00/\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00d\x00a\x00t\x00a\x00b\x00a\x00s\x00e\x00 \x00c\x00o\x00n\x00t\x00e\x00x\x00t\x00 \x00t\x00o\x00 \x00'\x00S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00'\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xe3\x08\x00\x07\x05\t\x04\x00\x01\x00\x00\xe3\x17\x00\x02\nu\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00\x00\xabn\x00G\x16\x00\x00\x01\x00'\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00l\x00a\x00n\x00g\x00u\x00a\x00g\x00e\x00 \x00s\x00e\x00t\x00t\x00i\x00n\x00g\x00 \x00t\x00o\x00 \x00u\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xad6\x00\x01s\x0b\x00\x03\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\n\x00\x15\x88\xe3\x13\x00\x04\x044\x000\x009\x006\x00\x044\x000\x009\x006\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ])
        tds = _TdsSocket()
        tds._main_session = _TdsSession(tds, tds)
        tds._sock = sock
        tds._main_session.process_login_tokens()

        # test invalid tds version
        sock = _FakeSock([
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00\x06m\x00a\x00s\x00t\x00e\x00r\x00\xab~\x00E\x16\x00\x00\x02\x00/\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00d\x00a\x00t\x00a\x00b\x00a\x00s\x00e\x00 \x00c\x00o\x00n\x00t\x00e\x00x\x00t\x00 \x00t\x00o\x00 \x00'\x00S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00'\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xe3\x08\x00\x07\x05\t\x04\x00\x01\x00\x00\xe3\x17\x00\x02\nu\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00\x00\xabn\x00G\x16\x00\x00\x01\x00'\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00l\x00a\x00n\x00g\x00u\x00a\x00g\x00e\x00 \x00s\x00e\x00t\x00t\x00i\x00n\x00g\x00 \x00t\x00o\x00 \x00u\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xad6\x00\x01\x65\x0b\x00\x03\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\n\x00\x15\x88\xe3\x13\x00\x04\x044\x000\x009\x006\x00\x044\x000\x009\x006\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ])
        tds = _TdsSocket()
        tds._main_session = _TdsSession(tds, tds)
        tds._sock = sock
        with self.assertRaises(InterfaceError):
            tds._main_session.process_login_tokens()

        # test for invalid env type
        sock = _FakeSock([
            b"\x04\x01\x01\xad\x00Z\x01\x00\xe3/\x00\x01\x10S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00\x06m\x00a\x00s\x00t\x00e\x00r\x00\xab~\x00E\x16\x00\x00\x02\x00/\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00d\x00a\x00t\x00a\x00b\x00a\x00s\x00e\x00 \x00c\x00o\x00n\x00t\x00e\x00x\x00t\x00 \x00t\x00o\x00 \x00'\x00S\x00u\x00b\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00P\x00o\x00r\x00t\x00a\x00l\x00'\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xe3\x08\x00\xab\x05\t\x04\x00\x01\x00\x00\xe3\x17\x00\x02\nu\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00\x00\xabn\x00G\x16\x00\x00\x01\x00'\x00C\x00h\x00a\x00n\x00g\x00e\x00d\x00 \x00l\x00a\x00n\x00g\x00u\x00a\x00g\x00e\x00 \x00s\x00e\x00t\x00t\x00i\x00n\x00g\x00 \x00t\x00o\x00 \x00u\x00s\x00_\x00e\x00n\x00g\x00l\x00i\x00s\x00h\x00.\x00\tM\x00S\x00S\x00Q\x00L\x00H\x00V\x003\x000\x00\x00\x01\x00\x00\x00\xad6\x00\x01s\x0b\x00\x03\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\n\x00\x15\x88\xe3\x13\x00\x04\x044\x000\x009\x006\x00\x044\x000\x009\x006\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ])
        tds = _TdsSocket()
        tds._main_session = _TdsSession(tds, tds)
        tds._sock = sock
        tds._main_session.process_login_tokens()
