import json
import urllib.request
import urllib.parse
import unittest
import settings
from pytds import (
    connect,
)


LIVE_TEST = getattr(settings, "LIVE_TEST", True)


@unittest.skipUnless(LIVE_TEST, "requires HOST variable to be set")
def test_fedauth_connection():
    kwargs = settings.CONNECT_KWARGS.copy()
    kwargs.update(
        {
            "user": None,
            "password": None,
            "access_token_callable": get_access_token
        }
    )

    with connect(**kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("select 1")
            assert cur.fetchall() == [(1,)]


def get_access_token():
    tenant_id = settings.TENANT_ID
    client_id = settings.CLIENT_ID
    client_secret = settings.CLIENT_SECRET

    # Authority and scope
    AUTHORITY = f'https://login.microsoftonline.com/{tenant_id}'
    TOKEN_URL = f'{AUTHORITY}/oauth2/v2.0/token'
    SCOPE = 'https://database.windows.net/.default'

    # Encode the form data
    data = urllib.parse.urlencode({
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': SCOPE,
        'grant_type': 'client_credentials',
    }).encode('utf-8')

    # Build and send the request
    req = urllib.request.Request(
        TOKEN_URL,
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    with urllib.request.urlopen(req) as response:
        resp_data = response.read()
        return json.loads(resp_data)["access_token"]

