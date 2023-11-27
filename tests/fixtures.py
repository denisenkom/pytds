import logging

import pytest
import sqlalchemy.engine
from sqlalchemy import create_engine

import pytds.tds_socket
import settings
import sqlalchemy_schema
import utils


logger = logging.getLogger(__name__)
LIVE_TEST = getattr(settings, "LIVE_TEST", True)
pytds.tds_base.logging_enabled = True


@pytest.fixture(scope="module")
def db_connection(sqlalchemy_engine):
    if not LIVE_TEST:
        pytest.skip("LIVE_TEST is not set")
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs["database"] = settings.DATABASE
    conn = pytds.connect(*settings.CONNECT_ARGS, **kwargs)
    utils.create_test_database(connection=conn)
    conn.commit()
    return conn


@pytest.fixture
def cursor(db_connection):
    with db_connection.cursor() as cursor:
        yield cursor
    db_connection.rollback()


@pytest.fixture
def separate_db_connection():
    if not LIVE_TEST:
        pytest.skip("LIVE_TEST is not set")
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs["database"] = settings.DATABASE
    conn = pytds.connect(*settings.CONNECT_ARGS, **kwargs)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def collation_set(db_connection):
    with db_connection.cursor() as cursor:
        cursor.execute(
            "SELECT Name, Description, COLLATIONPROPERTY(Name, 'LCID') FROM ::fn_helpcollations()"
        )
        collations_list = cursor.fetchall()
    return set(coll_name for coll_name, _, _ in collations_list)


@pytest.fixture(scope="module")
def sqlalchemy_engine() -> sqlalchemy.engine.Engine:
    host = settings.HOST
    hostname, _, instance = host.partition("\\")
    url = f"mssql+pytds://{settings.USER}:{settings.PASSWORD}@/{settings.DATABASE}?host={host}"
    engine = create_engine(
        url,
        echo=True,
    )
    sqlalchemy_schema.Base.metadata.create_all(engine)
    return engine
