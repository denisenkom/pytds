import os
import pytds

HOST = os.environ['HOST']
DATABASE = os.environ['DATABASE']
USER = os.environ['SQLUSER']
PASSWORD = os.environ['SQLPASSWORD']
USE_MARS = os.environ['usemars']

CONNECT_ARGS = []
CONNECT_KWARGS = {
    'server': HOST,
    'database': DATABASE,
    'user': USER,
    'password': PASSWORD,
    'autocommit': False,
    'readonly': True,
    'use_mars': USE_MARS,
    'tds_version': getattr(pytds, os.environ['tds_version']),
    }
