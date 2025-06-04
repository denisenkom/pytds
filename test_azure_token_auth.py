import pytest
from pytds import connect
from pytds.login import AzureTokenAuth
import settings

LIVE_TEST = getattr(settings, "LIVE_TEST", True)

@pytest.mark.skipif(not LIVE_TEST, reason="LIVE_TEST is not enabled")
def test_connection_with_azure_token():
    """
    Test Azure SQL connection using access token.
    Requires LIVE_TEST to be enabled and valid Azure SQL credentials set.
    """
    token = "YOUR_ACCESS_TOKEN"  # Replace with actual token
    server = "YOUR_SERVER.database.windows.net"  # Replace with actual server
    database = "YOUR_DATABASE"  # Replace with actual database

    auth = AzureTokenAuth(server=server, database=database, token=token)
    conn = connect(auth_token=auth)

    with conn.cursor() as cur:
        cur.execute("SELECT 1")
        result = cur.fetchone()
        assert result[0] == 1
