import os
import pytds

HOST = os.environ['HOST']
DATABASE = os.environ['DATABASE']
USER = os.environ['SQLUSER']
PASSWORD = os.environ['SQLPASSWORD']
USE_MARS = bool(os.environ.get('USE_MARS'))

CONNECT_ARGS = []
CONNECT_KWARGS = {
    'server': HOST,
    'database': DATABASE,
    'user': USER,
    'password': PASSWORD,
    'use_mars': USE_MARS,
    }

if 'tds_version' in os.environ:
    CONNECT_KWARGS['tds_version'] = getattr(pytds, os.environ['tds_version'])

if 'auth' in os.environ:
    import pytds.login
    CONNECT_KWARGS['auth'] = getattr(pytds.login, os.environ['auth'])()
