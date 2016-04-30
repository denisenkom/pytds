# vim: set fileencoding=utf8 :
from __future__ import with_statement
import os
import codecs
from six import StringIO

from pytds.tds_types import TimeType, DateTime2Type, DateType, DateTimeOffsetType, BitType, TinyIntType, SmallIntType, \
    IntType, BigIntType, RealType, FloatType, NVarCharType, VarBinaryType, SmallDateTimeType, DateTimeType, DecimalType, \
    MoneyType, UniqueIdentifierType, VariantType, ImageType, VarBinaryMaxType, VarCharType, TextType, NTextType, \
    NVarCharMaxType, VarCharMaxType, XmlType

try:
    import unittest2 as unittest
except:
    import unittest
import sys
from decimal import Decimal, getcontext
import logging
from time import sleep
from datetime import datetime, date, time
import uuid
import pytds.tz
import pytds.login
tzoffset = pytds.tz.FixedOffsetTimezone
utc = pytds.tz.utc
import pytds.extensions
from six import text_type
from six.moves import xrange
from pytds import (
    connect, ProgrammingError, TimeoutError, Time, SimpleLoadBalancer, LoginError,
    Error, IntegrityError, Timestamp, DataError, DECIMAL, Date, Binary,
    NotSupportedError,
    output, default, InterfaceError, TDS_ENCRYPTION_OFF,
    STRING, BINARY, NUMBER, DATETIME, DECIMAL, INTEGER, REAL, XML)
from pytds.tds import (
    _TdsSocket, _TdsSession, TDS_ENCRYPTION_REQUIRE, Column, BitSerializer, IntSerializer, SmallIntSerializer,
    NVarChar72Serializer, TinyIntSerializer, IntNSerializer, BigIntSerializer, RealSerializer, FloatSerializer, FloatNSerializer, Collation, DateTimeSerializer,
    IS_TDS73_PLUS, IS_TDS71_PLUS, TDS73, TDS71, TDS72, TDS70,
    TDS_ENCRYPTION_OFF,
    SmallMoneyType)
import dbapi20
import pytds
import settings


# set decimal precision to match mssql maximum precision
getcontext().prec = 38


#logging.basicConfig(level='DEBUG')
#logging.basicConfig(level='INFO')
logging.basicConfig()

LIVE_TEST = getattr(settings, 'LIVE_TEST', True)

@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestCase(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def tearDown(self):
        self.conn.close()


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class NoMarsTestCase(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['use_mars'] = False
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def tearDown(self):
        self.conn.close()

    def test_commit(self):
        cursor = self.conn.cursor()
        cursor.execute('select 1')
        cursor.fetchall()
        self.conn.commit()


class DbTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not LIVE_TEST:
            return
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['autocommit'] = True
        with connect(**kwargs) as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute('drop database [{0}]'.format(settings.DATABASE))
                except:
                    pass
                cur.execute('create database [{0}]'.format(settings.DATABASE))

    @classmethod
    def tearDownClass(cls):
        if not LIVE_TEST:
            return
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['server'] = settings.HOST
        kwargs['database'] = 'master'
        kwargs['autocommit'] = True
        with connect(**kwargs) as conn:
            with conn.cursor() as cur:
                cur.execute('drop database [{0}]'.format(settings.DATABASE))

    def setUp(self):
        self.conn = pytds.connect(*settings.CONNECT_ARGS, **settings.CONNECT_KWARGS)

    def tearDown(self):
        self.conn.close()


class TestCase2(TestCase):
    def test_all(self):
        cur = self.conn.cursor()
        with self.assertRaises(ProgrammingError):
            cur.execute(u'select ')
        self.assertEqual('abc', cur.execute_scalar("select cast('abc' as varchar(max)) as fieldname"))
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
        assert None == cur.execute_scalar("select cast(NULL as xml)")
        self.assertEqual(None, cur.execute_scalar("select cast(NULL as varchar(max)) as fieldname"))
        assert None == cur.execute_scalar("select cast(NULL as nvarchar(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as varchar(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as nchar(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
        assert None == cur.execute_scalar("select cast(NULL as char(10)) as fieldname")
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
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['login_timeout'] = 1
        kwargs['timeout'] = 1
        with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
            cur = conn.cursor()
            with self.assertRaises(TimeoutError):
                cur.execute("waitfor delay '00:00:05'")
            cur.execute('select 1')

    def test_timeout_no_mars(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['login_timeout'] = 1
        kwargs['timeout'] = 1
        kwargs['use_mars'] = False
        conn = connect(*settings.CONNECT_ARGS, **kwargs)
        with conn.cursor() as cur:
            with self.assertRaises(TimeoutError):
                cur.execute("waitfor delay '00:00:05'")
        with conn.cursor() as cur:
            cur.execute("select 1")
            cur.fetchall()

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
        self.assertEqual(sess.state, 'SESSION ESTABLISHED')
        sess.close()
        self.assertEqual(sess.state, 'CLOSED')

    def test_cursor_env(self):
        with self.conn.cursor() as cur:
            cur.execute('use master')
            self.assertEqual(cur.execute_scalar('select DB_NAME()'), 'master')

    def test_empty_query(self):
        with self.conn.cursor() as cur:
            cur.execute('')
            self.assertIs(None, cur.description)

    def test_parameters_ll(self):
        _params_tests(self)

    def _test_val(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select %s', (val,))
            self.assertTupleEqual(cur.fetchone(), (val,))
            self.assertIs(cur.fetchone(), None)

    def test_parameters(self):
        test_val = self._test_val

        test_val(u'hello')
        test_val(u'x' * 5000)
        test_val(123)
        test_val(-123)
        test_val(123.12)
        test_val(-123.12)
        test_val(10 ** 20)
        test_val(10 ** 38 - 1)
        test_val(-10 ** 38 + 1)
        test_val(datetime(2011, 2, 3, 10, 11, 12, 3000))
        test_val(Decimal('1234.567'))
        test_val(Decimal('1234000'))
        test_val(Decimal('9' * 38))
        test_val(Decimal('0.' + '9' * 38))
        test_val(-Decimal('9' * 38))
        test_val(Decimal('1E10'))
        test_val(Decimal('1E-10'))
        test_val(Decimal('0.{0}1'.format('0' * 37)))
        test_val(None)
        test_val('hello')
        test_val('')
        test_val(Binary(b''))
        test_val(Binary(b'\x00\x01\x02'))
        test_val(Binary(b'x' * 9000))
        test_val(2 ** 63 - 1)
        test_val(False)
        test_val(True)
        test_val(uuid.uuid4())
        test_val(u'Iñtërnâtiônàlizætiøn1')
        test_val(u'\U0001d6fc')

    def test_varcharmax(self):
        self._test_val('x' * 9000)

    def test_overlimit(self):
        def test_val(val):
            with self.conn.cursor() as cur:
                cur.execute('select %s', (val,))
                self.assertTupleEqual(cur.fetchone(), (val,))
                self.assertIs(cur.fetchone(), None)

        ##cur.execute('select %s', '\x00'*(2**31))
        with self.assertRaises(DataError):
            test_val(Decimal('1' + '0' * 38))
        with self.assertRaises(DataError):
            test_val(Decimal('-1' + '0' * 38))
        with self.assertRaises(DataError):
            test_val(Decimal('1E38'))
        with self.conn.cursor() as cur:
            val = -10 ** 38
            cur.execute('select %s', (val,))
            self.assertTupleEqual(cur.fetchone(), (str(val),))
            self.assertIs(cur.fetchone(), None)

    def test_description(self):
        with self.conn.cursor() as cur:
            cur.execute('select cast(12.65 as decimal(4,2)) as testname')
            self.assertEqual(cur.description[0][0], 'testname')
            self.assertEqual(cur.description[0][1], DECIMAL)
            self.assertEqual(cur.description[0][4], 4)
            self.assertEqual(cur.description[0][5], 2)

    def test_bug4(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            set transaction isolation level read committed
            select 1
            ''')
            self.assertEqual(cur.fetchall(), [(1,)])

    def test_bad_collation(self):
        with self.conn.cursor() as cur:
            try:
                cur.execute_scalar('select cast(0x90 as varchar)')
            except:
                pass
            self.assertEqual(1, cur.execute_scalar('select 1'))

    def test_get_instances(self):
        if not hasattr(settings, 'BROWSER_ADDRESS'):
            return unittest.skip('BROWSER_ADDRESS setting is not defined')
        pytds.tds.tds7_get_instances(settings.BROWSER_ADDRESS)

    def test_isolation_level(self):
        # enable autocommit and then reenable to force new transaction to be started
        self.conn.autocommit = True
        self.conn.isolation_level = pytds.extensions.ISOLATION_LEVEL_SERIALIZABLE
        self.conn.autocommit = False
        with self.conn.cursor() as cur:
            cur.execute('select transaction_isolation_level '
                        'from sys.dm_exec_sessions where session_id = @@SPID')
            lvl, = cur.fetchone()
        self.assertEqual(pytds.extensions.ISOLATION_LEVEL_SERIALIZABLE, lvl)

    def test_fetch_on_empty_dataset(self):
        with self.conn.cursor() as cur:
            cur.execute('declare @x int')
            with self.assertRaises(ProgrammingError):
                cur.fetchall()


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
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

    def _test_bulk_type(self, typ, value):
        with self.conn.cursor() as cur:
            cur.execute('create table bulk_insert_table_ll(c1 {0})'.format(typ.get_declaration()))
            cur._session.submit_plain_query('insert bulk bulk_insert_table_ll (c1 {0})'.format(typ.get_declaration()))
            cur._session.process_simple_request()
            col1 = Column(name='c1', type=typ, flags=Column.fNullable)
            metadata = [col1]
            cur._session.submit_bulk(metadata, [(value,)])
            cur._session.process_simple_request()
        with self.conn.cursor() as cur:
            cur.execute('select c1 from bulk_insert_table_ll')
            self.assertTupleEqual(cur.fetchone(), (value,))
            self.assertIs(cur.fetchone(), None)
            cur.execute('drop table bulk_insert_table_ll')

    def test_bulk_insert_low_level(self):
        self._test_bulk_type(BitType(), True)
        self._test_bulk_type(BitType(), False)
        self._test_bulk_type(IntType(), 2 ** 31 - 1)
        self._test_bulk_type(IntType(), -2 ** 31)
        self._test_bulk_type(SmallIntType(), -2 ** 15)
        self._test_bulk_type(SmallIntType(), 2 ** 15 - 1)
        self._test_bulk_type(TinyIntType(), 255)
        self._test_bulk_type(TinyIntType(), 0)
        self._test_bulk_type(BigIntType(), 2 ** 63 - 1)
        self._test_bulk_type(BigIntType(), -2 ** 63)
        self._test_bulk_type(TinyIntType(), 255)
        self._test_bulk_type(SmallIntType(), 2 ** 15 - 1)
        self._test_bulk_type(IntType(), 2 ** 31 - 1)
        self._test_bulk_type(BigIntType(), 2 ** 63 - 1)
        self._test_bulk_type(IntType(), None)
        self._test_bulk_type(RealType(), None)
        self._test_bulk_type(RealType(), 0.25)
        self._test_bulk_type(FloatType(), None)
        self._test_bulk_type(FloatType(), 0.25)
        self._test_bulk_type(NVarCharType(size=10), u'')
        self._test_bulk_type(NVarCharType(size=10), u'testtest12')
        self._test_bulk_type(NVarCharType(size=10), None)
        self._test_bulk_type(NVarCharType(size=4000), u'x' * 4000)
        self._test_bulk_type(VarBinaryType(size=10), b'')
        self._test_bulk_type(VarBinaryType(size=10), b'testtest12')
        self._test_bulk_type(VarBinaryType(size=10), None)
        self._test_bulk_type(VarBinaryType(size=8000), b'x' * 8000)
        self._test_bulk_type(SmallDateTimeType(), datetime(1900, 1, 1, 0, 0, 0))
        self._test_bulk_type(SmallDateTimeType(), datetime(2079, 6, 6, 23, 59, 0))
        self._test_bulk_type(DateTimeType(), datetime(1753, 1, 1, 0, 0, 0))
        self._test_bulk_type(DateTimeType(), datetime(9999, 12, 31, 23, 59, 59, 990000))
        self._test_bulk_type(SmallDateTimeType(), datetime(1900, 1, 1, 0, 0, 0))
        self._test_bulk_type(DateTimeType(), datetime(9999, 12, 31, 23, 59, 59, 990000))
        self._test_bulk_type(DateTimeType(), None)
        self._test_bulk_type(DateType(), date(1, 1, 1))
        self._test_bulk_type(DateType(), date(9999, 12, 31))
        self._test_bulk_type(DateType(), None)
        self._test_bulk_type(TimeType(precision=0), time(0, 0, 0))
        self._test_bulk_type(TimeType(precision=6), time(23, 59, 59, 999999))
        self._test_bulk_type(TimeType(precision=0), None)
        self._test_bulk_type(DateTime2Type(precision=0), datetime(1, 1, 1, 0, 0, 0))
        self._test_bulk_type(DateTime2Type(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999))
        self._test_bulk_type(DateTime2Type(precision=0), None)
        self._test_bulk_type(DateTimeOffsetType(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999, utc))
        self._test_bulk_type(DateTimeOffsetType(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999, tzoffset(14)))
        self._test_bulk_type(DateTimeOffsetType(precision=0), datetime(1, 1, 1, 0, 0, 0, tzinfo=tzoffset(-14)))
        self._test_bulk_type(DateTimeOffsetType(precision=0), datetime(1, 1, 1, 0, 14, 0, tzinfo=tzoffset(14)))
        self._test_bulk_type(DateTimeOffsetType(precision=6), None)
        self._test_bulk_type(DecimalType(scale=6, precision=38), Decimal('123.456789'))
        self._test_bulk_type(DecimalType(scale=6, precision=38), None)
        self._test_bulk_type(SmallMoneyType(), Decimal('214748.3647'))
        self._test_bulk_type(SmallMoneyType(), Decimal('-214748.3648'))
        self._test_bulk_type(MoneyType(), Decimal('922337203685477.5807'))
        self._test_bulk_type(MoneyType(), Decimal('-922337203685477.5808'))
        self._test_bulk_type(SmallMoneyType(), Decimal('214748.3647'))
        self._test_bulk_type(MoneyType(), Decimal('922337203685477.5807'))
        self._test_bulk_type(MoneyType(), None)
        self._test_bulk_type(UniqueIdentifierType(), None)
        self._test_bulk_type(UniqueIdentifierType(), uuid.uuid4())
        self._test_bulk_type(VariantType(), None)
        #self._test_bulk_type(VariantType(), 100)
        #self._test_bulk_type(ImageType(), None)
        self._test_bulk_type(VarBinaryMaxType(), None)
        #self._test_bulk_type(NTextType(), None)
        #self._test_bulk_type(TextType(), None)
        #self._test_bulk_type(ImageType(), b'')
        #self._test_bulk_type(self.conn._conn._type_factory.long_binary_type(), b'testtest12')
        self._test_bulk_type(self.conn._conn._type_factory.long_string_type(), None)
        self._test_bulk_type(self.conn._conn._type_factory.long_varchar_type(), None)
        #self._test_bulk_type(self.conn._conn._type_factory.long_string_type(), 'test')
        #self._test_bulk_type(ImageType(), None)
        #self._test_bulk_type(ImageType(), None)
        #self._test_bulk_type(ImageType(), b'test')

    def test_bulk_insert(self):
        with self.conn.cursor() as cur:
            cur.execute('create table bulk_insert_table(num int, data varchar(100))')
            f = StringIO("42\tfoo\n74\tbar\n")
            cur.copy_to(f, 'bulk_insert_table', columns=('num', 'data'))
            cur.execute('select num, data from bulk_insert_table')
            self.assertListEqual(cur.fetchall(), [(42, 'foo'), (74, 'bar')])

    def test_table_valued_type_autodetect(self):
        def rows_gen():
            yield (1, 'test1')
            yield (2, 'test2')

        with self.conn.cursor() as cur:
            cur.execute('CREATE TYPE dbo.CategoryTableType AS TABLE ( CategoryID int, CategoryName nvarchar(50) )')
            self.conn.commit()

            tvp = pytds.TableValuedParam(type_name='dbo.CategoryTableType', rows=rows_gen())
            cur.execute('SELECT * FROM %s', (tvp,))
            self.assertEqual(cur.fetchall(), [(1, 'test1'), (2, 'test2')])

            cur.execute('DROP TYPE dbo.CategoryTableType')
            self.conn.commit()

    def test_table_valued_type_explicit(self):
        def rows_gen():
            yield (1, 'test1')
            yield (2, 'test2')

        with self.conn.cursor() as cur:
            cur.execute('CREATE TYPE dbo.CategoryTableType AS TABLE ( CategoryID int, CategoryName nvarchar(50) )')
            self.conn.commit()

            tvp = pytds.TableValuedParam(
                type_name='dbo.CategoryTableType',
                columns=(Column(type=IntType()), Column(type=NVarCharType(size=30))),
                rows=rows_gen())
            cur.execute('SELECT * FROM %s', (tvp,))
            self.assertEqual(cur.fetchall(), [(1, 'test1'), (2, 'test2')])

            cur.execute('DROP TYPE dbo.CategoryTableType')
            self.conn.commit()

    def test_table_selects(self):
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

        cur = self.conn.cursor()
        cur.execute(u'drop table #testtable')

    def test_stored_proc(self):
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
        values = cur.callproc('testproc', (val, default, output(value=1)))
        #self.assertEqual(cur.fetchall(), [(val,)])
        self.assertEqual(val + 2, values[2])
        self.assertEqual(val + 2, cur.get_proc_return_status())

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

    def test_cursor_closing(self):
        with self.conn.cursor() as cur:
            cur.execute('select 10; select 12')
            cur.fetchone()
        with self.conn.cursor() as cur2:
            cur2.execute('select 20')
            cur2.fetchone()

    def test_transactions(self):
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

        with self.conn.cursor() as cur:
            cur.execute('''
            if object_id('testtable') is not null
                drop table testtable
            ''')
        self.conn.commit()

    def test_manual_commit(self):
        self.conn.autocommit = False
        cur = self.conn.cursor()
        cur.execute("create table tbl(x int)")
        self.assertTrue(self.conn._conn.tds72_transaction)
        try:
            cur.execute("create table tbl(x int)")
        except:
            pass
        trancount = cur.execute_scalar("select @@trancount")
        self.assertEqual(1, trancount, 'Should be in transaction even after errors')

        cur.execute("create table tbl(x int)")
        try:
            cur.execute("create table tbl(x int)")
        except:
            pass
        cur.callproc('sp_executesql', ('select @@trancount',))
        trancount, = cur.fetchone()
        self.assertEqual(1, trancount, 'Should be in transaction even after errors')

    def test_multi_packet(self):
        cur = self.conn.cursor()
        param = 'x' * (self.conn._conn.main_session._writer.bufsize * 3)
        cur.execute('select %s', (param,))
        self.assertEqual([(param, )], cur.fetchall())

    def test_big_request(self):
        with self.conn.cursor() as cur:
            param = 'x' * 5000
            params = (10, datetime(2012, 11, 19, 1, 21, 37, 3000), param, 'test')
            cur.execute('select %s, %s, %s, %s', params)
            self.assertEqual([params], cur.fetchall())

    def test_row_count(self):
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
        self.assertEqual(cur.rowcount, 2)

    def test_no_rows(self):
        cur = self.conn.cursor()
        cur.execute('''
        create table testtable (field int)
        ''')
        cur.execute('select * from testtable')
        self.assertEqual([], cur.fetchall())

    def test_fixed_size_data(self):
        with self.conn.cursor() as cur:
            cur.execute('''
            create table testtable (chr char(5), nchr nchar(5), bfld binary(5))
            insert into testtable values ('1', '2', cast('3' as binary(5)))
            ''')
            cur.execute('select * from testtable')
            self.assertEqual(cur.fetchall(), [('1    ', '2    ', b'3\x00\x00\x00\x00')])


class TestVariant(TestCase):
    def _t(self, result, sql):
        with self.conn.cursor() as cur:
            cur.execute("select cast({0} as sql_variant)".format(sql))
            val, = cur.fetchone()
            self.assertEqual(result, val)

    def test_new_datetime(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')
        import pytds.tz
        self._t(datetime(2011, 2, 3, 10, 11, 12, 3000), "cast('2011-02-03T10:11:12.003000' as datetime2)")
        self._t(time(10, 11, 12, 3000), "cast('10:11:12.003000' as time)")
        self._t(date(2011, 2, 3), "cast('2011-02-03' as date)")
        self._t(datetime(2011, 2, 3, 10, 11, 12, 3000, pytds.tz.FixedOffsetTimezone(3 * 60)), "cast('2011-02-03T10:11:12.003000+03:00' as datetimeoffset)")

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
        self._t(val, "cast('{0}' as uniqueidentifier)".format(val))
        self._t(True, "cast(1 as bit)")
        self._t(128, "cast(128 as tinyint)")
        self._t(255, "cast(255 as tinyint)")
        self._t(-32000, "cast(-32000 as smallint)")
        self._t(2000000000, "cast(2000000000 as int)")
        self._t(2000000000000, "cast(2000000000000 as bigint)")
        self._t(0.12345, "cast(0.12345 as float)")
        self._t(0.25, "cast(0.25 as real)")
        self._t(Decimal('922337203685477.5807'), "cast('922,337,203,685,477.5807' as money)")
        self._t(Decimal('-214748.3648'), "cast('- 214,748.3648' as smallmoney)")


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class BadConnection(unittest.TestCase):
    def test_invalid_parameters(self):
        with self.assertRaises(Error):
            with connect(server=settings.HOST + 'bad', database='master', user='baduser', password=settings.PASSWORD, login_timeout=5) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
        with self.assertRaises(Error):
            with connect(server=settings.HOST, database='doesnotexist', user=settings.USER, password=settings.PASSWORD) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
        with self.assertRaises(Error):
            with connect(server=settings.HOST, database='master', user='baduser', password=None) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')

    def test_instance_and_port(self):
        host = settings.HOST
        if '\\' in host:
            host, _ = host.split('\\')
        with self.assertRaisesRegexp(ValueError, 'Both instance and port shouldn\'t be specified'):
            with connect(server=host + '\\badinstancename', database='master', user=settings.USER, password=settings.PASSWORD, port=1212) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')


def get_spid(conn):
    with conn.cursor() as cur:
        return cur.spid


def kill(conn, spid):
    with conn.cursor() as cur:
        cur.execute('kill {0}'.format(spid))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class ConnectionClosing(unittest.TestCase):
    def test_open_close(self):
        for x in xrange(3):
            kwargs = settings.CONNECT_KWARGS.copy()
            kwargs['database'] = 'master'
            connect(**kwargs).close()

    def test_closing_after_closed_by_server(self):
        """
        You should be able to call close on connection closed by server
        """
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['autocommit'] = True
        with connect(**kwargs) as master_conn:
            kwargs['autocommit'] = False
            with connect(**kwargs) as conn:
                with conn.cursor() as cur:
                    cur.execute('select 1')
                    conn.commit()
                    kill(master_conn, get_spid(conn))
                    sleep(0.2)
                conn.close()

    def test_connection_closed_by_server(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        with connect(**kwargs) as master_conn:
            master_conn.autocommit = True
            with connect(**kwargs) as conn:
                conn.autocommit = False
                # test overall recovery
                with conn.cursor() as cur:
                    cur.execute('select 1')
                    conn.commit()
                    kill(master_conn, get_spid(conn))
                    sleep(0.2)
                    cur.execute('select 1')
                    cur.fetchall()
                kill(master_conn, get_spid(conn))
                sleep(0.2)
                with conn.cursor() as cur:
                    cur.execute('select 1')

                # test recovery on transaction
                with conn.cursor() as cur:
                    cur.execute('create table ##testtable3 (fld int)')
                    kill(master_conn, get_spid(conn))
                    sleep(0.2)
                    with self.assertRaises(Exception):
                        cur.execute('select * from ##testtable2')
                        cur.fetchall()
                    conn.rollback()
                    cur.execute('select 1')
            #with connect(server=settings.HOST, database='master', user=settings.USER, password=settings.PASSWORD) as conn:
            #    spid = get_spid(conn)
            #    with conn.cursor() as cur:
            #        # test recovery of specific lowlevel methods
            #        tds_submit_query(cur._session, "waitfor delay '00:00:05'; select 1")
            #        kill(master_conn, spid)
            #        self.assertTrue(cur._session.is_connected())
            #        with self.assertRaises(Exception):
            #            tds_process_tokens(cur._session, TDS_TOKEN_RESULTS)
            #        self.assertFalse(cur._session.is_connected())


#class EncryptionTest(unittest.TestCase):
#    def runTest(self):
#        conn = connect(server=settings.HOST, database='master', user=settings.USER, password=settings.PASSWORD, encryption_level=TDS_ENCRYPTION_REQUIRE)
#        cur = conn.cursor()
#        cur.execute('select 1')


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
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


class Extensions(TestCase):
    def runTest(self):
        with self.conn.cursor() as cur:
            self.assertEqual(cur.connection, self.conn)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
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


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class DateTimeTest(DbTestCase):
    def _testencdec(self, val):
        self.assertEqual(val, DateTimeSerializer.decode(*DateTimeSerializer._struct.unpack(DateTimeSerializer.encode(val))))

    def _testval(self, val):
        with self.conn.cursor() as cur:
            cur.execute('select cast(%s as datetime)', (val,))
            self.assertEqual(cur.fetchall(), [(val,)])

    def runTest(self):
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
                import pytds.tz
                cur.tzinfo_factory = pytds.tz.FixedOffsetTimezone
                cur.execute('select cast(%s as datetimeoffset)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])

        with self.conn.cursor() as cur:
            import pytds.tz
            cur.tzinfo_factory = pytds.tz.FixedOffsetTimezone
            cur.execute("select cast('2010-01-02T20:21:22.1234567+05:00' as datetimeoffset)")
            self.assertEqual(datetime(2010, 1, 2, 20, 21, 22, 123456, tzoffset(5 * 60)), cur.fetchone()[0])
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, utc))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(5 * 60)))
        _testval(Timestamp(1, 1, 1, 0, 0, 0, 0, utc))
        _testval(Timestamp(9999, 12, 31, 23, 59, 59, 999999, utc))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(14)))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(-14)))
        _testval(Timestamp(2010, 1, 2, 0, 0, 0, 0, tzoffset(-15)))

    def test_time(self):
        if not IS_TDS73_PLUS(self.conn):
            self.skipTest('Requires TDS7.3+')

        def testval(val):
            with self.conn.cursor() as cur:
                cur.execute('select cast(%s as time)', (val,))
                self.assertEqual(cur.fetchall(), [(val,)])

        testval(Time(14, 16, 18, 123456))
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


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class Auth(unittest.TestCase):
    @unittest.skipUnless(os.getenv('NTLM_USER') and os.getenv('NTLM_PASSWORD'), "requires HOST variable to be set")
    def test_ntlm(self):
        conn = connect(settings.HOST, auth=pytds.login.NtlmAuth(user_name=os.getenv('NTLM_USER'), password=os.getenv('NTLM_PASSWORD')))
        with conn.cursor() as cursor:
            cursor.execute('select 1')
            cursor.fetchall()

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
    def test_sspi(self):
        from pytds.login import SspiAuth
        with connect(settings.HOST, auth=SspiAuth()) as conn:
            with conn.cursor() as cursor:
                cursor.execute('select 1')
                cursor.fetchall()

    @unittest.skipIf(getattr(settings, 'SKIP_SQL_AUTH', False), 'SKIP_SQL_AUTH is set')
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
    def test_cancel(self):
        self.conn.cursor().cancel()


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestIntegrityError(DbTestCase):
    def test_primary_key(self):
        cursor = self.conn.cursor()
        cursor.execute('create table testtable(pk int primary key)')
        cursor.execute('insert into testtable values (1)')
        with self.assertRaises(IntegrityError):
            cursor.execute('insert into testtable values (1)')


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TimezoneTests(unittest.TestCase):
    def check_val(self, conn, sql, input, output):
        with conn.cursor() as cur:
            cur.execute('select ' + sql, (input,))
            rows = cur.fetchall()
            self.assertEqual(rows[0][0], output)

    def runTest(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        use_tz = utc
        kwargs['use_tz'] = use_tz
        kwargs['database'] = 'master'
        with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
            # Naive time should be interpreted as use_tz
            self.check_val(conn, '%s',
                           datetime(2011, 2, 3, 10, 11, 12, 3000),
                           datetime(2011, 2, 3, 10, 11, 12, 3000, utc))
            # Aware time shoule be passed as-is
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset(1))
            self.check_val(conn, '%s', dt, dt)
            # Aware time should be converted to use_tz if not using datetimeoffset type
            dt = datetime(2011, 2, 3, 10, 11, 12, 3000, tzoffset(1))
            if IS_TDS73_PLUS(conn):
                self.check_val(conn, 'cast(%s as datetime2)', dt, dt.astimezone(use_tz))


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class DbapiTestSuite(dbapi20.DatabaseAPI20Test, DbTestCase):
    driver = pytds
    connect_args = settings.CONNECT_ARGS
    connect_kw_args = settings.CONNECT_KWARGS

#    def _connect(self):
#        return connection

    def _try_run(self, *args):
        with self._connect() as con:
            with con.cursor() as cur:
                for arg in args:
                    cur.execute(arg)

    def _try_run2(self, cur, *args):
        for arg in args:
            cur.execute(arg)

    # This should create the "lower" sproc.
    def _callproc_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[to_lower]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[to_lower]""",
            """
            CREATE PROCEDURE to_lower
                @input nvarchar(max)
            AS
            BEGIN
                select LOWER(@input)
            END
            """,
            )

    # This should create a sproc with a return value.
    def _retval_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[add_one]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[add_one]""",
            """
CREATE PROCEDURE add_one (@input int)
AS
BEGIN
    return @input+1
END
""",
            )

    def test_retval(self):
        with self._connect() as con:
            cur = con.cursor()
            self._retval_setup(cur)
            values = cur.callproc('add_one', (1,))
            self.assertEqual(values[0], 1, 'input parameter should be left unchanged: %s' % (values[0],))

            self.assertEqual(cur.description, None, "No resultset was expected.")
            self.assertEqual(cur.return_value, 2, "Invalid return value: %s" % (cur.return_value,))

        # This should create a sproc with a return value.
    def _retval_select_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[add_one_select]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[add_one_select]""",
            """
CREATE PROCEDURE add_one_select (@input int)
AS
BEGIN
    select 'a' as a
    select 'b' as b
    return @input+1
END
""",
            )

    def test_retval_select(self):
        with self._connect() as con:
            cur = con.cursor()
            self._retval_select_setup(cur)
            values = cur.callproc('add_one_select', (1,))
            self.assertEqual(values[0], 1, 'input parameter should be left unchanged: %s' % (values[0],))

            self.assertEqual(len(cur.description), 1, "Unexpected resultset.")
            self.assertEqual(cur.description[0][0], 'a', "Unexpected resultset.")
            self.assertEqual(cur.fetchall(), [('a',)], 'Unexpected resultset.')
            
            self.assertTrue(cur.nextset(), 'No second resultset found.')
            self.assertEqual(len(cur.description), 1, "Unexpected resultset.")
            self.assertEqual(cur.description[0][0], 'b', "Unexpected resultset.")
            
            self.assertEqual(cur.return_value, 2, "Invalid return value: %s" % (cur.return_value,))
            with self.assertRaises(Error):
                cur.fetchall()

    # This should create a sproc with an output parameter.
    def _outparam_setup(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[add_one_out]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[add_one_out]""",
            """
CREATE PROCEDURE add_one_out (@input int, @output int OUTPUT)
AS
BEGIN
    SET @output = @input+1
END
""",
            )

    def test_outparam(self):
        with self._connect() as con:
            cur = con.cursor()
            self._outparam_setup(cur)
            values = cur.callproc('add_one_out', (1, output(value=1)))
            self.assertEqual(len(values), 2, 'expected 2 parameters')
            self.assertEqual(values[0], 1, 'input parameter should be unchanged')
            self.assertEqual(values[1], 2, 'output parameter should get new values')

            values = cur.callproc('add_one_out', (None, output(value=1)))
            self.assertEqual(len(values), 2, 'expected 2 parameters')
            self.assertEqual(values[0], None, 'input parameter should be unchanged')
            self.assertEqual(values[1], None, 'output parameter should get new values')

    def test_outparam_null_default(self):
        with self.assertRaises(ValueError):
            output(None, None)

        with self._connect() as con:
            cur = con.cursor()
            cur.execute('''
            create procedure testproc (@inparam int, @outint int = 8 output, @outstr varchar(max) = 'defstr' output)
            as
            begin
                set nocount on
                set @outint = isnull(@outint, -10) + @inparam
                set @outstr = isnull(@outstr, 'null') + cast(@inparam as varchar(max))
                set @inparam = 8
            end
            ''')
            values = cur.callproc('testproc', (1, output(value=4), output(value='str')))
            self.assertEqual([1, 5, 'str1'], values)
            values = cur.callproc('testproc', (1, output(value=None, param_type='int'), output(value=None, param_type='varchar(max)')))
            self.assertEqual([1, -9, 'null1'], values)
            values = cur.callproc('testproc', (1, output(value=default, param_type='int'), output(value=default, param_type='varchar(max)')))
            self.assertEqual([1, 9, 'defstr1'], values)
            values = cur.callproc('testproc', (1, output(value=default, param_type='bit'), output(value=default, param_type='varchar(5)')))
            self.assertEqual([1, 1, 'defst'], values)
            values = cur.callproc('testproc', (1, output(value=default, param_type=int), output(value=default, param_type=str)))
            self.assertEqual([1, 9, 'defstr1'], values)

    def test_assigning_select(self):
        # test that assigning select does not interfere with result sets
        with self._connect() as con:
            cur = con.cursor()
            cur.execute("""
declare @var1 int

select @var1 = 1
select @var1 = 2

select 'value'
""")
            self.assertFalse(cur.description)
            self.assertTrue(cur.nextset())
            
            self.assertFalse(cur.description)
            self.assertTrue(cur.nextset())
            
            self.assertTrue(cur.description)
            self.assertEqual([(u'value',)], cur.fetchall())
            self.assertFalse(cur.nextset())

            cur.execute("""
set nocount on

declare @var1 int

select @var1 = 1
select @var1 = 2

select 'value'
""")
            self.assertTrue(cur.description)
            self.assertEqual([(u'value',)], cur.fetchall())
            self.assertFalse(cur.nextset())

    # Don't need setoutputsize tests.
    def test_setoutputsize(self):
        pass

    def help_nextset_setUp(self, cur):
        self._try_run2(
            cur,
            """IF OBJECT_ID(N'[dbo].[deleteme]', N'P') IS NOT NULL DROP PROCEDURE [dbo].[deleteme]""",
            """
create procedure deleteme
as
begin
    select count(*) from %sbooze
    select name from %sbooze
end
""" % (self.table_prefix, self.table_prefix),
            )

    def help_nextset_tearDown(self, cur):
        cur.execute("drop procedure deleteme")

    def test_ExceptionsAsConnectionAttributes(self):
        pass

    def test_select_decimal_zero(self):
        with self._connect() as con:
            expected = (
                Decimal('0.00'),
                Decimal('0.0'),
                Decimal('-0.00'))

            cur = con.cursor()
            cur.execute("SELECT %s as A, %s as B, %s as C", expected)

            result = cur.fetchall()
            self.assertEqual(result[0], expected)

    def test_type_objects(self):
        with self._connect() as con:
            cur = con.cursor()
            cur.execute("""
select cast(0 as varchar), 
       cast(1 as binary),
       cast(2 as int),
       cast(3 as real),
       cast(4 as decimal),
       cast('2005' as datetime),
       cast('6' as xml)
""")
            self.assertTrue(cur.description)
            col_types = [col[1] for col in cur.description]
            self.assertEqual(col_types[0], STRING)
            self.assertEqual(col_types[1], BINARY)
            self.assertEqual(col_types[2], NUMBER)
            self.assertEqual(col_types[2], INTEGER)
            self.assertEqual(col_types[3], NUMBER)
            self.assertEqual(col_types[3], REAL)
            # self.assertEqual(col_types[4], NUMBER) ?
            self.assertEqual(col_types[4], DECIMAL)
            self.assertEqual(col_types[5], DATETIME)
            self.assertEqual(col_types[6], XML)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestBug4(unittest.TestCase):
    def test_as_dict(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        with connect(*settings.CONNECT_ARGS, **kwargs) as conn:
            conn.as_dict = True
            with conn.cursor() as cur:
                cur.execute('select 1 as a, 2 as b')
                self.assertDictEqual({'a': 1, 'b': 2}, cur.fetchone())


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TransactionsTests(DbTestCase):
    def test_rollback_timeout_recovery(self):
        self.conn.autocommit = False
        with self.conn.cursor() as cur:
            cur.execute('''
            create table testtable_rollback (field int)
            ''')
            sql = 'insert into testtable_rollback values ' + ','.join(['(1)'] * 1000)
            for i in xrange(10):
                cur.execute(sql)

        self.conn._conn._sock.settimeout(0.00001)
        try:
            self.conn.rollback()
        except:
            pass

        self.conn._conn._sock.settimeout(10)
        cur = self.conn.cursor()
        cur.execute('select 1')
        cur.fetchall()

    def test_commit_timeout_recovery(self):
        self.conn.autocommit = False
        with self.conn.cursor() as cur:
            cur.execute('''
            create table testtable (field int)
            ''')
            sql = 'insert into testtable values ' + ','.join(['(1)'] * 1000)
            for i in xrange(10):
                cur.execute(sql)

        self.conn._conn._sock.settimeout(0.00001)
        try:
            self.conn.commit()
        except:
            pass

        self.conn._conn._sock.settimeout(10)
        cur = self.conn.cursor()
        cur.execute('select 1')
        cur.fetchall()


def _params_tests(self):
    def test_val(typ, val):
        with self.conn.cursor() as cur:
            param = Column(type=typ, value=val)
            cur.execute('select %s', [param])
            self.assertTupleEqual(cur.fetchone(), (val,))
            self.assertIs(cur.fetchone(), None)

    test_val(BitType(), True)
    test_val(BitType(), False)
    test_val(BitType(), None)
    test_val(TinyIntType(), 255)
    test_val(SmallIntType(), 2 ** 15 - 1)
    test_val(IntType(), 2 ** 31 - 1)
    test_val(BigIntType(), 2 ** 63 - 1)
    test_val(IntType(), None)
    test_val(RealType(), 0.25)
    test_val(FloatType(), 0.25)
    test_val(RealType(), None)
    test_val(SmallDateTimeType(), datetime(1900, 1, 1, 0, 0, 0))
    test_val(SmallDateTimeType(), datetime(2079, 6, 6, 23, 59, 0))
    test_val(DateTimeType(), datetime(1753, 1, 1, 0, 0, 0))
    test_val(DateTimeType(), datetime(9999, 12, 31, 23, 59, 59, 990000))
    test_val(DateTimeType(), None)
    if pytds.tds.IS_TDS73_PLUS(self.conn._conn):
        test_val(DateType(), date(1, 1, 1))
        test_val(DateType(), date(9999, 12, 31))
        test_val(DateType(), None)
        test_val(TimeType(precision=0), time(0, 0, 0))
        test_val(TimeType(precision=6), time(23, 59, 59, 999999))
        test_val(TimeType(precision=0), None)
        test_val(DateTime2Type(precision=0), datetime(1, 1, 1, 0, 0, 0))
        test_val(DateTime2Type(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999))
        test_val(DateTime2Type(precision=0), None)
        test_val(DateTimeOffsetType(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999, utc))
        test_val(DateTimeOffsetType(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999, tzoffset(14)))
        test_val(DateTimeOffsetType(precision=0), datetime(1, 1, 1, 0, 0, 0, tzinfo=tzoffset(-14)))
        #test_val(DateTimeOffsetType(precision=0), datetime(1, 1, 1, 0, 0, 0, tzinfo=tzoffset(14)))
        test_val(DateTimeOffsetType(precision=6), None)
    test_val(DecimalType(scale=6, precision=38), Decimal('123.456789'))
    test_val(DecimalType(scale=6, precision=38), None)
    test_val(SmallMoneyType(), Decimal('-214748.3648'))
    test_val(SmallMoneyType(), Decimal('214748.3647'))
    test_val(MoneyType(), Decimal('922337203685477.5807'))
    test_val(MoneyType(), Decimal('-922337203685477.5808'))
    test_val(MoneyType(), None)
    test_val(UniqueIdentifierType(), None)
    test_val(UniqueIdentifierType(), uuid.uuid4())
    if pytds.tds.IS_TDS71_PLUS(self.conn._conn):
        test_val(VariantType(), None)
        #test_val(self.conn._conn._type_factory.SqlVariant(10), 100)
    test_val(VarBinaryType(size=10), b'')
    test_val(VarBinaryType(size=10), b'testtest12')
    test_val(VarBinaryType(size=10), None)
    test_val(VarBinaryType(size=8000), b'x' * 8000)
    test_val(VarCharType(size=10), None)
    test_val(VarCharType(size=10), '')
    test_val(VarCharType(size=10), 'test')
    test_val(VarCharType(size=8000), 'x' * 8000)
    test_val(NVarCharType(size=10), u'')
    test_val(NVarCharType(size=10), u'testtest12')
    test_val(NVarCharType(size=10), None)
    test_val(NVarCharType(size=4000), u'x' * 4000)
    test_val(TextType(), None)
    test_val(TextType(), '')
    test_val(TextType(), 'hello')
    test_val(NTextType(), None)
    test_val(NTextType(), '')
    test_val(NTextType(), 'hello')
    test_val(ImageType(), None)
    test_val(ImageType(), b'')
    test_val(ImageType(), b'test')
    if pytds.tds.IS_TDS72_PLUS(self.conn._conn):
        test_val(VarBinaryMaxType(), None)
        test_val(VarBinaryMaxType(), b'')
        test_val(VarBinaryMaxType(), b'testtest12')
        test_val(VarBinaryMaxType(), b'x' * (10 ** 6))
        test_val(NVarCharMaxType(), None)
        test_val(NVarCharMaxType(), 'test')
        test_val(NVarCharMaxType(), 'x' * (10 ** 6))
        test_val(VarCharMaxType(), None)
        test_val(VarCharMaxType(), 'test')
        test_val(VarCharMaxType(), 'x' * (10 ** 6))
        test_val(XmlType(), '<root/>')


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds70(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds.TDS70
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds71(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds.TDS71
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds72(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds.TDS72
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds73A(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds.TDS73A
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds73B(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs['database'] = 'master'
        kwargs['tds_version'] = pytds.tds.TDS73B
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)
