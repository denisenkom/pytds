"""
Testing various ways of passing parameters to queries
"""
import unittest
import uuid
from datetime import datetime, date, time
from decimal import Decimal
from io import StringIO

from pytds import Column, connect
from pytds.tds_base import Param, default, output
from pytds.tds_types import (
    BitType,
    TinyIntType,
    SmallIntType,
    IntType,
    BigIntType,
    RealType,
    FloatType,
    SmallDateTimeType,
    DateTimeType,
    DateType,
    TimeType,
    DateTime2Type,
    DateTimeOffsetType,
    DecimalType,
    SmallMoneyType,
    MoneyType,
    UniqueIdentifierType,
    VariantType,
    VarBinaryType,
    VarCharType,
    NVarCharType,
    TextType,
    NTextType,
    ImageType,
    VarBinaryMaxType,
    NVarCharMaxType,
    VarCharMaxType,
    XmlType,
)
from fixtures import *
from pytds.tz import utc
from tests.all_test import tzoffset


def test_param_as_column_backward_compat(cursor):
    """
    For backward compatibility need to support passing parameters as Column objects
    New way to pass such parameters is to use Param object.
    """
    param = Column(type=BitType(), value=True)
    result = cursor.execute_scalar("select %s", [param])
    assert result is True


def test_param_with_spaces(cursor):
    """
    For backward compatibility need to support passing parameters as Column objects
    New way to pass such parameters is to use Param object.
    """
    result = cursor.execute_scalar("select %(param name)s", {"param name": "abc"})
    assert result == "abc"


def test_param_with_slashes(cursor):
    """
    For backward compatibility need to support passing parameters as Column objects
    New way to pass such parameters is to use Param object.
    """
    result = cursor.execute_scalar("select %(param/name)s", {"param/name": "abc"})
    assert result == "abc"


def test_dictionary_params(cursor):
    assert cursor.execute_scalar("select %(param)s", {"param": None}) == None
    assert cursor.execute_scalar("select %(param)s", {"param": 1}) == 1


def test_percent_escaping(cursor):
    # issue #171
    assert cursor.execute_scalar("select 'x %% y'") == "x %% y"
    assert cursor.execute_scalar("select 'x %% y'", {}) == "x % y"
    assert cursor.execute_scalar("select 'x %% y'", tuple()) == "x % y"


def test_overlimit(cursor):
    def test_val(val):
        cursor.execute("select %s", (val,))
        assert cursor.fetchone() == (val,)
        assert cursor.fetchone() is None

    ##cur.execute('select %s', '\x00'*(2**31))
    with pytest.raises(pytds.DataError):
        test_val(Decimal("1" + "0" * 38))
    with pytest.raises(pytds.DataError):
        test_val(Decimal("-1" + "0" * 38))
    with pytest.raises(pytds.DataError):
        test_val(Decimal("1E38"))
    val = -(10**38)
    cursor.execute("select %s", (val,))
    assert cursor.fetchone() == (str(val),)
    assert cursor.fetchone() is None


def test_outparam_and_result_set(cursor):
    """
    Test stored procedure which has output parameters and also result set
    """
    cur = cursor
    logger.info("creating stored procedure")
    cur.execute(
        """
    CREATE PROCEDURE P_OutParam_ResultSet(@A INT OUTPUT)
    AS BEGIN
    SET @A = 3;
    SELECT 4 AS C;
    SELECT 5 AS C;
    END;
    """
    )
    logger.info("executing stored procedure")
    cur.callproc("P_OutParam_ResultSet", [pytds.output(value=1)])
    assert [(4,)] == cur.fetchall()
    assert [3] == cur.get_proc_outputs()
    logger.info("execurint query after stored procedure")
    cur.execute("select 5")
    assert [(5,)] == cur.fetchall()


def test_outparam_null_default(cursor):
    with pytest.raises(ValueError):
        pytds.output(None, None)

    cur = cursor
    cur.execute(
        """
    create procedure outparam_null_testproc (@inparam int, @outint int = 8 output, @outstr varchar(max) = 'defstr' output)
    as
    begin
        set nocount on
        set @outint = isnull(@outint, -10) + @inparam
        set @outstr = isnull(@outstr, 'null') + cast(@inparam as varchar(max))
        set @inparam = 8
    end
    """
    )
    values = cur.callproc(
        "outparam_null_testproc", (1, pytds.output(value=4), pytds.output(value="str"))
    )
    assert [1, 5, "str1"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=None, param_type="int"),
            pytds.output(value=None, param_type="varchar(max)"),
        ),
    )
    assert [1, -9, "null1"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=pytds.default, param_type="int"),
            pytds.output(value=pytds.default, param_type="varchar(max)"),
        ),
    )
    assert [1, 9, "defstr1"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=pytds.default, param_type="bit"),
            pytds.output(value=pytds.default, param_type="varchar(5)"),
        ),
    )
    assert [1, 1, "defst"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=pytds.default, param_type=int),
            pytds.output(value=pytds.default, param_type=str),
        ),
    )
    assert [1, 9, "defstr1"] == values


def _params_tests(self):
    def test_val(typ, val):
        with self.conn.cursor() as cur:
            param = Param(type=typ, value=val)
            logger.info("Testing with %s", repr(param))
            cur.execute("select %s", [param])
            self.assertTupleEqual(cur.fetchone(), (val,))
            self.assertIs(cur.fetchone(), None)

    test_val(BitType(), True)
    test_val(BitType(), False)
    test_val(BitType(), None)
    test_val(TinyIntType(), 255)
    test_val(SmallIntType(), 2**15 - 1)
    test_val(IntType(), 2**31 - 1)
    test_val(BigIntType(), 2**63 - 1)
    test_val(IntType(), None)
    test_val(RealType(), 0.25)
    test_val(FloatType(), 0.25)
    test_val(RealType(), None)
    test_val(SmallDateTimeType(), datetime(1900, 1, 1, 0, 0, 0))
    test_val(SmallDateTimeType(), datetime(2079, 6, 6, 23, 59, 0))
    test_val(DateTimeType(), datetime(1753, 1, 1, 0, 0, 0))
    test_val(DateTimeType(), datetime(9999, 12, 31, 23, 59, 59, 990000))
    test_val(DateTimeType(), None)
    if pytds.tds_base.IS_TDS73_PLUS(self.conn._tds_socket):
        test_val(DateType(), date(1, 1, 1))
        test_val(DateType(), date(9999, 12, 31))
        test_val(DateType(), None)
        test_val(TimeType(precision=0), time(0, 0, 0))
        test_val(TimeType(precision=6), time(23, 59, 59, 999999))
        test_val(TimeType(precision=0), None)
        test_val(DateTime2Type(precision=0), datetime(1, 1, 1, 0, 0, 0))
        test_val(DateTime2Type(precision=6), datetime(9999, 12, 31, 23, 59, 59, 999999))
        test_val(DateTime2Type(precision=0), None)
        test_val(
            DateTimeOffsetType(precision=6),
            datetime(9999, 12, 31, 23, 59, 59, 999999, utc),
        )
        test_val(
            DateTimeOffsetType(precision=6),
            datetime(9999, 12, 31, 23, 59, 59, 999999, tzoffset(14)),
        )
        test_val(
            DateTimeOffsetType(precision=0),
            datetime(1, 1, 1, 0, 0, 0, tzinfo=tzoffset(-14)),
        )
        # test_val(DateTimeOffsetType(precision=0), datetime(1, 1, 1, 0, 0, 0, tzinfo=tzoffset(14)))
        test_val(DateTimeOffsetType(precision=6), None)
    test_val(DecimalType(scale=6, precision=38), Decimal("123.456789"))
    test_val(DecimalType(scale=6, precision=38), None)
    test_val(SmallMoneyType(), Decimal("-214748.3648"))
    test_val(SmallMoneyType(), Decimal("214748.3647"))
    test_val(MoneyType(), Decimal("922337203685477.5807"))
    test_val(MoneyType(), Decimal("-922337203685477.5808"))
    test_val(MoneyType(), None)
    test_val(UniqueIdentifierType(), None)
    test_val(UniqueIdentifierType(), uuid.uuid4())
    if pytds.tds_base.IS_TDS71_PLUS(self.conn._tds_socket):
        test_val(VariantType(), None)
        # test_val(self.conn._conn.type_factory.SqlVariant(10), 100)
    test_val(VarBinaryType(size=10), b"")
    test_val(VarBinaryType(size=10), b"testtest12")
    test_val(VarBinaryType(size=10), None)
    test_val(VarBinaryType(size=8000), b"x" * 8000)
    test_val(VarCharType(size=10), None)
    test_val(VarCharType(size=10), "")
    test_val(VarCharType(size=10), "test")
    test_val(VarCharType(size=8000), "x" * 8000)
    test_val(NVarCharType(size=10), "")
    test_val(NVarCharType(size=10), "testtest12")
    test_val(NVarCharType(size=10), None)
    test_val(NVarCharType(size=4000), "x" * 4000)
    test_val(TextType(), None)
    test_val(TextType(), "")
    test_val(TextType(), "hello")
    test_val(NTextType(), None)
    test_val(NTextType(), "")
    test_val(NTextType(), "hello")
    test_val(ImageType(), None)
    test_val(ImageType(), b"")
    test_val(ImageType(), b"test")
    if pytds.tds_base.IS_TDS72_PLUS(self.conn._tds_socket):
        test_val(VarBinaryMaxType(), None)
        test_val(VarBinaryMaxType(), b"")
        test_val(VarBinaryMaxType(), b"testtest12")
        test_val(VarBinaryMaxType(), b"x" * (10**6))
        test_val(NVarCharMaxType(), None)
        test_val(NVarCharMaxType(), "test")
        test_val(NVarCharMaxType(), "x" * (10**6))
        test_val(VarCharMaxType(), None)
        test_val(VarCharMaxType(), "test")
        test_val(VarCharMaxType(), "x" * (10**6))
        test_val(XmlType(), "<root/>")


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds70(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs["database"] = "master"
        kwargs["tds_version"] = pytds.tds_base.TDS70
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds71(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs["database"] = settings.DATABASE
        kwargs["tds_version"] = pytds.tds_base.TDS71
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)
        utils.create_test_database(self.conn)
        self.conn.commit()

    def test_parsing(self):
        _params_tests(self)

    def test_bulk(self):
        f = StringIO("42\tfoo\n74\tbar\n")
        with self.conn.cursor() as cur:
            cur.copy_to(
                f, "bulk_insert_table", schema="myschema", columns=("num", "data")
            )
            cur.execute("select num, data from myschema.bulk_insert_table")
            self.assertListEqual(cur.fetchall(), [(42, "foo"), (74, "bar")])

    def test_call_proc(self):
        with self.conn.cursor() as cur:
            val = 45
            values = cur.callproc("testproc", (val, default, output(value=1)))
            # self.assertEqual(cur.fetchall(), [(val,)])
            self.assertEqual(val + 2, values[2])
            self.assertEqual(val + 2, cur.get_proc_return_status())


def test_outparam_and_result_set(cursor):
    """
    Test stored procedure which has output parameters and also result set
    """
    cur = cursor
    logger.info("creating stored procedure")
    cur.execute(
        """
    CREATE PROCEDURE P_OutParam_ResultSet(@A INT OUTPUT)
    AS BEGIN
    SET @A = 3;
    SELECT 4 AS C;
    SELECT 5 AS C;
    END;
    """
    )
    logger.info("executing stored procedure")
    cur.callproc("P_OutParam_ResultSet", [pytds.output(value=1)])
    assert [(4,)] == cur.fetchall()
    assert [3] == cur.get_proc_outputs()
    logger.info("execurint query after stored procedure")
    cur.execute("select 5")
    assert [(5,)] == cur.fetchall()


def test_outparam_null_default(cursor):
    with pytest.raises(ValueError):
        pytds.output(None, None)

    cur = cursor
    cur.execute(
        """
    create procedure outparam_null_testproc (@inparam int, @outint int = 8 output, @outstr varchar(max) = 'defstr' output)
    as
    begin
        set nocount on
        set @outint = isnull(@outint, -10) + @inparam
        set @outstr = isnull(@outstr, 'null') + cast(@inparam as varchar(max))
        set @inparam = 8
    end
    """
    )
    values = cur.callproc(
        "outparam_null_testproc", (1, pytds.output(value=4), pytds.output(value="str"))
    )
    assert [1, 5, "str1"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=None, param_type="int"),
            pytds.output(value=None, param_type="varchar(max)"),
        ),
    )
    assert [1, -9, "null1"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=pytds.default, param_type="int"),
            pytds.output(value=pytds.default, param_type="varchar(max)"),
        ),
    )
    assert [1, 9, "defstr1"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=pytds.default, param_type="bit"),
            pytds.output(value=pytds.default, param_type="varchar(5)"),
        ),
    )
    assert [1, 1, "defst"] == values
    values = cur.callproc(
        "outparam_null_testproc",
        (
            1,
            pytds.output(value=pytds.default, param_type=int),
            pytds.output(value=pytds.default, param_type=str),
        ),
    )
    assert [1, 9, "defstr1"] == values


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds72(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs["database"] = "master"
        kwargs["tds_version"] = pytds.tds_base.TDS72
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds73A(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs["database"] = "master"
        kwargs["tds_version"] = pytds.tds_base.TDS73A
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
class TestTds73B(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs["database"] = "master"
        kwargs["tds_version"] = pytds.tds_base.TDS73B
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    def test_parsing(self):
        _params_tests(self)


class TestCaseWithCursor(unittest.TestCase):
    def setUp(self):
        kwargs = settings.CONNECT_KWARGS.copy()
        kwargs["database"] = "master"
        self.conn = connect(*settings.CONNECT_ARGS, **kwargs)

    # def test_mars_sessions_recycle_ids(self):
    #    if not self.conn.mars_enabled:
    #        self.skipTest('Only relevant to mars')
    #    for _ in range(2 ** 16 + 1):
    #        cur = self.conn.cursor()
    #        cur.close()

    def test_parameters_ll(self):
        _params_tests(self)
