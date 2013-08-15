import os

CONNECT_ARGS = []
CONNECT_KWARGS = {}

LIVE_TEST = 'HOST' in os.environ
if LIVE_TEST:
    HOST = os.environ['HOST']
    DATABASE=os.environ['DATABASE']
    USER=os.environ['SQLUSER']
    PASSWORD=os.environ['SQLPASSWORD']
    USE_MARS = bool(os.environ.get('USE_MARS'))
    SKIP_SQL_AUTH = bool(os.environ.get('SKIP_SQL_AUTH'))

    import pytds

    CONNECT_KWARGS = {
            'server': HOST,
            'database': DATABASE,
            'user': USER,
            'password': PASSWORD,
            'use_mars': USE_MARS,
            'bytes_to_unicode': True,
            }

    if 'tds_version' in os.environ:
        CONNECT_KWARGS['tds_version'] = getattr(pytds, os.environ['tds_version'])

    if 'auth' in os.environ:
        import pytds.login
        CONNECT_KWARGS['auth'] = getattr(pytds.login, os.environ['auth'])()

    if 'bytes_to_unicode' in os.environ:
        CONNECT_KWARGS['bytes_to_unicode'] = bool(os.environ.get('bytes_to_unicode'))
