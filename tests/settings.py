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

    import pytds

    CONNECT_KWARGS = {
            'server': HOST,
            'database': DATABASE,
            'user': USER,
            'password': PASSWORD,
            'use_mars': USE_MARS,
            'bytes_to_unicode': False,
            }

    if 'tds_version' in os.environ:
        CONNECT_KWARGS['tds_version'] = getattr(pytds, os.environ['tds_version'])
