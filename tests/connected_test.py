# vim: set fileencoding=utf8 :
from __future__ import with_statement
from __future__ import unicode_literals
from decimal import Decimal, Context
import uuid
import datetime
import logging
import random
import string
from io import BytesIO, StringIO

import pytest
import os
import pytds
import pytds.extensions
import pytds.login
import settings

from fixtures import *
from pytds import Column
from pytds.tds_types import BitType
from tests.utils import tran_count

logger = logging.getLogger(__name__)
LIVE_TEST = getattr(settings, "LIVE_TEST", True)
pytds.tds_base.logging_enabled = True


def test_integrity_error(cursor):
    cursor.execute("create table testtable_pk(pk int primary key)")
    cursor.execute("insert into testtable_pk values (1)")
    with pytest.raises(pytds.IntegrityError):
        cursor.execute("insert into testtable_pk values (1)")


def test_bulk_insert(cursor):
    cur = cursor
    f = StringIO("42\tfoo\n74\tbar\n")
    cur.copy_to(f, "bulk_insert_table", schema="myschema", columns=("num", "data"))
    cur.execute("select num, data from myschema.bulk_insert_table")
    assert [(42, "foo"), (74, "bar")] == cur.fetchall()


def test_bug2(cursor):
    cur = cursor
    cur.execute(
        """
    create procedure testproc_bug2 (@param int)
    as
    begin
        set transaction isolation level read uncommitted -- that will produce very empty result (even no rowcount)
        select @param
        return @param + 1
    end
    """
    )
    val = 45
    cur.execute("exec testproc_bug2 @param = 45")
    assert cur.fetchall() == [(val,)]
    assert val + 1 == cur.get_proc_return_status()


def test_stored_proc(cursor):
    cur = cursor
    val = 45
    # params = {'@param': val, '@outparam': output(None), '@add': 1}
    values = cur.callproc("testproc", (val, pytds.default, pytds.output(value=1)))
    # self.assertEqual(cur.fetchall(), [(val,)])
    assert val + 2 == values[2]
    assert val + 2 == cur.get_proc_return_status()

    # after calling stored proc which does not have RETURN statement get_proc_return_status() should return 0
    # since in this case SQL server issues RETURN STATUS token with 0 value
    cur.callproc("test_proc_no_return", (val,))
    assert cur.fetchall() == [(val,)]
    assert cur.get_proc_return_status() == 0

    # TODO fix this part, currently it fails
    # assert cur.execute_scalar("select 1") == 1
    # assert cur.get_proc_return_status() == 0


def test_table_selects(db_connection):
    cur = db_connection.cursor()
    cur.execute(
        """
    create table #testtable (id int, _text text, _xml xml, vcm varchar(max), vc varchar(10))
    """
    )
    cur.execute(
        """
    insert into #testtable (id, _text, _xml, vcm, vc) values (1, 'text', '<root/>', '', NULL)
    """
    )
    cur.execute("select id from #testtable order by id")
    assert [(1,)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute("select _text from #testtable order by id")
    assert [("text",)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute("select _xml from #testtable order by id")
    assert [("<root/>",)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute("select id, _text, _xml, vcm, vc from #testtable order by id")
    assert (1, "text", "<root/>", "", None) == cur.fetchone()

    cur = db_connection.cursor()
    cur.execute("select vc from #testtable order by id")
    assert [(None,)] == cur.fetchall()

    cur = db_connection.cursor()
    cur.execute("insert into #testtable (_xml) values (%s)", ("<some/>",))

    cur = db_connection.cursor()
    cur.execute("drop table #testtable")


def test_decimals(cursor):
    cur = cursor
    assert Decimal(12) == cur.execute_scalar("select cast(12 as decimal) as fieldname")
    assert Decimal(-12) == cur.execute_scalar(
        "select cast(-12 as decimal) as fieldname"
    )
    assert Decimal("123456.12345") == cur.execute_scalar(
        "select cast('123456.12345'as decimal(20,5)) as fieldname"
    )
    assert Decimal("-123456.12345") == cur.execute_scalar(
        "select cast('-123456.12345'as decimal(20,5)) as fieldname"
    )


def test_bulk_insert_with_special_chars_no_columns(cursor):
    cur = cursor
    cur.execute("create table [test]] table](num int not null, data varchar(100))")
    f = StringIO("42\tfoo\n74\tbar\n")
    cur.copy_to(f, "test] table")
    cur.execute("select num, data from [test]] table]")
    assert cur.fetchall() == [(42, "foo"), (74, "bar")]


def test_bulk_insert_with_special_chars(cursor):
    cur = cursor
    cur.execute("create table [test]] table](num int, data varchar(100))")
    f = StringIO("42\tfoo\n74\tbar\n")
    cur.copy_to(f, "test] table", columns=("num", "data"))
    cur.execute("select num, data from [test]] table]")
    assert cur.fetchall() == [(42, "foo"), (74, "bar")]


def test_bulk_insert_with_keyword_column_name(cursor):
    cur = cursor
    cur.execute("create table test_table(num int, [User] varchar(100))")
    f = StringIO("42\tfoo\n74\tbar\n")
    cur.copy_to(f, "test_table")
    cur.execute("select num, [User] from test_table")
    assert cur.fetchall() == [(42, "foo"), (74, "bar")]


def test_bulk_insert_with_direct_data(cursor):
    cur = cursor
    cur.execute("create table test_table(num int, data nvarchar(max))")

    data = [[42, "foo"], [57, ""], [66, None], [74, "bar"]]

    column_types = [
        pytds.tds_base.Column("num", type=pytds.tds_types.IntType()),
        pytds.tds_base.Column("data", type=pytds.tds_types.NVarCharMaxType()),
    ]

    cur.copy_to(data=data, table_or_view="test_table", columns=column_types)
    cur.execute("select num, data from test_table")
    assert cur.fetchall() == [(42, "foo"), (57, ""), (66, None), (74, "bar")]


def test_table_valued_type_autodetect(cursor):
    def rows_gen():
        yield 1, "test1"
        yield 2, "test2"

    tvp = pytds.TableValuedParam(type_name="dbo.CategoryTableType", rows=rows_gen())
    cursor.execute("SELECT * FROM %s", (tvp,))
    assert cursor.fetchall() == [(1, "test1"), (2, "test2")]


def test_table_valued_type_explicit(cursor):
    def rows_gen():
        yield 1, "test1"
        yield 2, "test2"

    tvp = pytds.TableValuedParam(
        type_name="dbo.CategoryTableType",
        columns=(
            pytds.Column(type=pytds.tds_types.IntType()),
            pytds.Column(type=pytds.tds_types.NVarCharType(size=30)),
        ),
        rows=rows_gen(),
    )
    cursor.execute("SELECT * FROM %s", (tvp,))
    assert cursor.fetchall() == [(1, "test1"), (2, "test2")]


def test_minimal(cursor):
    cursor.execute("select 1")
    assert [(1,)] == cursor.fetchall()


def test_empty_query(cursor):
    cursor.execute("")
    assert cursor.description is None


@pytest.mark.parametrize(
    "typ,values",
    [
        (pytds.tds_types.BitType(), [True, False]),
        (pytds.tds_types.IntType(), [2**31 - 1, None]),
        (pytds.tds_types.IntType(), [-(2**31), None]),
        (pytds.tds_types.SmallIntType(), [-(2**15), 2**15 - 1]),
        (pytds.tds_types.TinyIntType(), [255, 0]),
        (pytds.tds_types.BigIntType(), [2**63 - 1, -(2**63)]),
        (pytds.tds_types.IntType(), [None, 2**31 - 1]),
        (pytds.tds_types.IntType(), [None, -(2**31)]),
        (pytds.tds_types.RealType(), [0.25, None]),
        (pytds.tds_types.FloatType(), [0.25, None]),
        (pytds.tds_types.VarCharType(size=10), ["", "testtest12", None, "foo"]),
        (pytds.tds_types.VarCharType(size=4000), ["x" * 4000, "foo"]),
        (
            pytds.tds_types.VarCharMaxType(),
            ["x" * 10000, "foo", "", "testtest", None, "bar"],
        ),
        (pytds.tds_types.NVarCharType(size=10), ["", "testtest12", None, "foo"]),
        (pytds.tds_types.NVarCharType(size=4000), ["x" * 4000, "foo"]),
        (
            pytds.tds_types.NVarCharMaxType(),
            ["x" * 10000, "foo", "", "testtest", None, "bar"],
        ),
        (pytds.tds_types.VarBinaryType(size=10), [b"testtest12", b"", None]),
        (pytds.tds_types.VarBinaryType(size=8000), [b"x" * 8000, b""]),
        (
            pytds.tds_types.SmallDateTimeType(),
            [
                datetime.datetime(1900, 1, 1, 0, 0, 0),
                None,
                datetime.datetime(2079, 6, 6, 23, 59, 0),
            ],
        ),
        (
            pytds.tds_types.DateTimeType(),
            [
                datetime.datetime(1753, 1, 1, 0, 0, 0),
                None,
                datetime.datetime(9999, 12, 31, 23, 59, 59, 990000),
            ],
        ),
        (
            pytds.tds_types.DateType(),
            [datetime.date(1, 1, 1), None, datetime.date(9999, 12, 31)],
        ),
        (pytds.tds_types.TimeType(precision=0), [datetime.time(0, 0, 0), None]),
        (
            pytds.tds_types.TimeType(precision=6),
            [datetime.time(23, 59, 59, 999999), None],
        ),
        (pytds.tds_types.TimeType(precision=0), [None]),
        (
            pytds.tds_types.DateTime2Type(precision=0),
            [datetime.datetime(1, 1, 1, 0, 0, 0), None],
        ),
        (
            pytds.tds_types.DateTime2Type(precision=6),
            [datetime.datetime(9999, 12, 31, 23, 59, 59, 999999), None],
        ),
        (pytds.tds_types.DateTime2Type(precision=0), [None]),
        (
            pytds.tds_types.DateTimeOffsetType(precision=6),
            [datetime.datetime(9999, 12, 31, 23, 59, 59, 999999, pytds.tz.utc), None],
        ),
        (
            pytds.tds_types.DateTimeOffsetType(precision=6),
            [
                datetime.datetime(
                    9999, 12, 31, 23, 59, 59, 999999, pytds.tz.FixedOffsetTimezone(14)
                ),
                None,
            ],
        ),
        (
            pytds.tds_types.DateTimeOffsetType(precision=0),
            [
                datetime.datetime(
                    1, 1, 1, 0, 0, 0, tzinfo=pytds.tz.FixedOffsetTimezone(-14)
                )
            ],
        ),
        (
            pytds.tds_types.DateTimeOffsetType(precision=0),
            [
                datetime.datetime(
                    1, 1, 1, 0, 14, 0, tzinfo=pytds.tz.FixedOffsetTimezone(14)
                )
            ],
        ),
        (pytds.tds_types.DateTimeOffsetType(precision=6), [None]),
        (
            pytds.tds_types.DecimalType(scale=6, precision=38),
            [Decimal("123.456789"), None],
        ),
        (
            pytds.tds_types.SmallMoneyType(),
            [Decimal("214748.3647"), None, Decimal("-214748.3648")],
        ),
        (
            pytds.tds_types.MoneyType(),
            [Decimal("922337203685477.5807"), None, Decimal("-922337203685477.5808")],
        ),
        (pytds.tds_types.SmallMoneyType(), [Decimal("214748.3647")]),
        (pytds.tds_types.MoneyType(), [Decimal("922337203685477.5807")]),
        (pytds.tds_types.MoneyType(), [None]),
        (pytds.tds_types.UniqueIdentifierType(), [None, uuid.uuid4()]),
        (pytds.tds_types.VariantType(), [None]),
        # (pytds.tds_types.VariantType(), [100]),
        # (pytds.tds_types.ImageType(), [None]),
        (pytds.tds_types.VarBinaryMaxType(), [None]),
        # (pytds.tds_types.NTextType(), [None]),
        # (pytds.tds_types.TextType(), [None]),
        # (pytds.tds_types.ImageType(), [b'']),
        # (self.conn._conn.type_factory.long_binary_type(), [b'testtest12']),
        # (self.conn._conn.type_factory.long_string_type(), [None]),
        # (self.conn._conn.type_factory.long_varchar_type(), [None]),
        # (self.conn._conn.type_factory.long_string_type(), ['test']),
        # (pytds.tds_types.ImageType(), [None]),
        # (pytds.tds_types.ImageType(), [None]),
        # (pytds.tds_types.ImageType(), [b'test']),
    ],
)
def test_bulk_insert_type(cursor, typ, values):
    cur = cursor
    cur.execute(
        "create table bulk_insert_table_ll(c1 {0})".format(typ.get_declaration())
    )
    cur._session.submit_plain_query(
        "insert bulk bulk_insert_table_ll (c1 {0})".format(typ.get_declaration())
    )
    cur._session.process_simple_request()
    col1 = pytds.Column(name="c1", type=typ, flags=pytds.Column.fNullable)
    metadata = [col1]
    cur._session.submit_bulk(metadata, [[value] for value in values])
    cur._session.process_simple_request()
    cur.execute("select c1 from bulk_insert_table_ll")
    assert cur.fetchall() == [(value,) for value in values]
    assert cur.fetchone() is None


def test_streaming(cursor):
    val = "x" * 10000
    # test nvarchar(max)
    cursor.execute("select N'{}', 1".format(val))
    with pytest.raises(ValueError):
        cursor.set_stream(1, StringIO())
    with pytest.raises(ValueError):
        cursor.set_stream(2, StringIO())
    with pytest.raises(ValueError):
        cursor.set_stream(-1, StringIO())
    cursor.set_stream(0, StringIO())
    row = cursor.fetchone()
    assert isinstance(row[0], StringIO)
    assert row[0].getvalue() == val

    # test nvarchar(max) with NULL value
    cursor.execute("select cast(NULL as nvarchar(max)), 1".format(val))
    cursor.set_stream(0, StringIO())
    row = cursor.fetchone()
    assert row[0] is None

    # test varchar(max)
    cursor.execute("select '{}', 1".format(val))
    cursor.set_stream(0, StringIO())
    row = cursor.fetchone()
    assert isinstance(row[0], StringIO)
    assert row[0].getvalue() == val

    # test varbinary(max)
    cursor.execute("select cast('{}' as varbinary(max)), 1".format(val))
    cursor.set_stream(0, BytesIO())
    row = cursor.fetchone()
    assert isinstance(row[0], BytesIO)
    assert row[0].getvalue().decode("ascii") == val

    # test image type
    cursor.execute("select cast('{}' as image), 1".format(val))
    cursor.set_stream(0, BytesIO())
    row = cursor.fetchone()
    assert isinstance(row[0], BytesIO)
    assert row[0].getvalue().decode("ascii") == val

    # test ntext type
    cursor.execute("select cast('{}' as ntext), 1".format(val))
    cursor.set_stream(0, StringIO())
    row = cursor.fetchone()
    assert isinstance(row[0], StringIO)
    assert row[0].getvalue() == val

    # test text type
    cursor.execute("select cast('{}' as text), 1".format(val))
    cursor.set_stream(0, StringIO())
    row = cursor.fetchone()
    assert isinstance(row[0], StringIO)
    assert row[0].getvalue() == val

    # test xml type
    xml_val = "<root>{}</root>".format(val)
    cursor.execute("select cast('{}' as xml), 1".format(xml_val))
    cursor.set_stream(0, StringIO())
    row = cursor.fetchone()
    assert isinstance(row[0], StringIO)
    assert row[0].getvalue() == xml_val


def test_properties(separate_db_connection):
    conn = separate_db_connection
    # this property is provided for compatibility with pymssql
    assert conn.autocommit_state == conn.autocommit
    # test set_autocommit which is provided for compatibility with ADO dbapi
    conn.set_autocommit(conn.autocommit)
    # test isolation_level property read/write
    conn.isolation_level = conn.isolation_level
    # test product_version property read
    logger.info("Product version %s", conn.product_version)
    conn.as_dict = conn.as_dict


def test_fetch_on_empty_dataset(cursor):
    cursor.execute("declare @x int")
    with pytest.raises(pytds.ProgrammingError):
        cursor.fetchall()


def test_bad_collation(cursor):
    # exception can be different
    with pytest.raises(UnicodeDecodeError):
        cursor.execute_scalar("select cast(0x90 as varchar)")
    # check that connection is still usable
    assert 1 == cursor.execute_scalar("select 1")


def test_description(cursor):
    cursor.execute("select cast(12.65 as decimal(4,2)) as testname")
    assert cursor.description[0][0] == "testname"
    assert cursor.description[0][1] == pytds.DECIMAL
    assert cursor.description[0][4] == 4
    assert cursor.description[0][5] == 2


def test_bug4(separate_db_connection):
    with separate_db_connection.cursor() as cursor:
        cursor.execute(
            """
        set transaction isolation level read committed
        select 1
        """
        )
        assert cursor.fetchall() == [(1,)]


def test_row_strategies(separate_db_connection):
    conn = pytds.connect(
        *settings.CONNECT_ARGS,
        **settings.CONNECT_KWARGS,
        row_strategy=pytds.dict_row_strategy,
    )
    with conn.cursor() as cur:
        cur.execute("select 1 as f")
        assert cur.fetchall() == [{"f": 1}]
    conn = pytds.connect(
        *settings.CONNECT_ARGS,
        **settings.CONNECT_KWARGS,
        row_strategy=pytds.tuple_row_strategy,
    )
    with conn.cursor() as cur:
        cur.execute("select 1 as f")
        assert cur.fetchall() == [(1,)]


def test_fetchone(cursor):
    cur = cursor
    cur.execute("select 10; select 12")
    assert (10,) == cur.fetchone()
    assert cur.nextset()
    assert (12,) == cur.fetchone()
    assert not cur.nextset()


def test_fetchall(cursor):
    cur = cursor
    cur.execute("select 10; select 12")
    assert [(10,)] == cur.fetchall()
    assert cur.nextset()
    assert [(12,)] == cur.fetchall()
    assert not cur.nextset()


def test_cursor_closing(db_connection):
    with db_connection.cursor() as cur:
        cur.execute("select 10; select 12")
        cur.fetchone()
    with db_connection.cursor() as cur2:
        cur2.execute("select 20")
        cur2.fetchone()


def test_multi_packet(cursor):
    cur = cursor
    param = "x" * (cursor._connection._tds_socket.main_session._writer.bufsize * 3)
    cur.execute("select %s", (param,))
    assert [(param,)] == cur.fetchall()


def test_big_request(cursor):
    cur = cursor
    param = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(5000)
    )
    params = (10, datetime.datetime(2012, 11, 19, 1, 21, 37, 3000), param, "test")
    cur.execute("select %s, %s, %s, %s", params)
    assert [params] == cur.fetchall()


def test_row_count(cursor):
    cur = cursor
    cur.execute(
        """
    create table testtable_row_cnt (field int)
    """
    )
    cur.execute("insert into testtable_row_cnt (field) values (1)")
    assert cur.rowcount == 1
    cur.execute("insert into testtable_row_cnt (field) values (2)")
    assert cur.rowcount == 1
    cur.execute("select * from testtable_row_cnt")
    cur.fetchall()
    assert cur.rowcount == 2


def test_no_rows(cursor):
    cur = cursor
    cur.execute(
        """
    create table testtable_no_rows (field int)
    """
    )
    cur.execute("select * from testtable_no_rows")
    assert [] == cur.fetchall()


def test_fixed_size_data(cursor):
    cur = cursor
    cur.execute(
        """
    create table testtable_fixed_size_dt (chr char(5), nchr nchar(5), bfld binary(5))
    insert into testtable_fixed_size_dt values ('1', '2', cast('3' as binary(5)))
    """
    )
    cur.execute("select * from testtable_fixed_size_dt")
    assert cur.fetchall() == [("1    ", "2    ", b"3\x00\x00\x00\x00")]


def test_closing_cursor_in_context(db_connection):
    with db_connection.cursor() as cur:
        cur.close()


def test_cursor_connection_property(db_connection):
    with db_connection.cursor() as cur:
        assert cur.connection is db_connection


@pytest.mark.skipif(
    not utils.hashlib_supports_md4(),
    reason="Current python version does not support MD4 which is needed for NTLM"
)
def test_invalid_ntlm_creds():
    if not LIVE_TEST:
        pytest.skip("LIVE_TEST is not set")
    with pytest.raises(pytds.OperationalError):
        pytds.connect(
            settings.HOST, auth=pytds.login.NtlmAuth(user_name="bad", password="bad")
        )


def test_open_with_different_blocksize():
    if not LIVE_TEST:
        pytest.skip("LIVE_TEST is not set")
    kwargs = settings.CONNECT_KWARGS.copy()
    # test very small block size
    kwargs["blocksize"] = 100
    with pytds.connect(*settings.CONNECT_ARGS, **kwargs):
        pass
    # test very large block size
    kwargs["blocksize"] = 1000000
    with pytds.connect(*settings.CONNECT_ARGS, **kwargs):
        pass


def test_nvarchar_multiple_rows(cursor):
    cursor.execute(
        """
    set nocount on
    declare @tbl table (id int primary key, fld nvarchar(max))
    insert into @tbl values(1, 'foo')
    insert into @tbl values(2, 'bar')
    select fld from @tbl order by id
    """
    )
    assert cursor.fetchall() == [("foo",), ("bar",)]


def test_no_metadata_request(cursor):
    cursor._session.submit_rpc(
        rpc_name=pytds.tds_base.SP_PREPARE,
        params=cursor._session._convert_params(
            (pytds.output(param_type=int), "@p1 int", "select @p1")
        ),
    )
    cursor._session.begin_response()
    cursor._session.process_rpc()
    while cursor.nextset():
        pass
    res = cursor.get_proc_outputs()
    handle = res[0]
    logger.info("got handle %s", handle)
    cursor._session.submit_rpc(
        rpc_name=pytds.tds_base.SP_EXECUTE,
        params=cursor._session._convert_params((handle, 1)),
    )
    cursor._session.begin_response()
    cursor._session.process_rpc()
    assert cursor.fetchall() == [(1,)]
    while cursor.nextset():
        pass
    cursor._session.submit_rpc(
        rpc_name=pytds.tds_base.SP_EXECUTE,
        params=cursor._session._convert_params((handle, 2)),
        flags=0x02,  # no metadata
    )
    cursor._session.begin_response()
    cursor._session.process_rpc()
    # for some reason SQL server still sends metadata back
    assert cursor.fetchall() == [(2,)]
    while cursor.nextset():
        pass


def test_with_sso():
    if not LIVE_TEST:
        pytest.skip("LIVE_TEST is not set")
    with pytds.connect(settings.HOST, use_sso=True) as conn:
        with conn.cursor() as cursor:
            cursor.execute("select 1")
            cursor.fetchall()
