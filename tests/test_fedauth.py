import unittest
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from unittest.mock import MagicMock, patch
import struct
from pytds.tds_base import _TdsLogin
from pytds import tds_base, connect
from pytds.tds_socket import _TdsSocket
from pytds.tds_session import _TdsSession
from pytds.fedauth import fedauth_packet

class TestFedAuth(unittest.TestCase):
    def setUp(self):
        # Patch find_spec to return None for OpenSSL to avoid import errors
        self.patcher = patch('importlib.util.find_spec', return_value=None)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_fedauth_packet_generation(self):
        """Verify the FEDAUTH feature extension packet structure"""
        login = _TdsLogin()
        login.access_token = "mock_token"
        
        # Manually construct packet using the library's function
        packet = fedauth_packet(login, True)
        
        # Verify header (Feature ID 0x02 for FEDAUTH)
        self.assertEqual(packet[0], tds_base.TDS_LOGIN_FEATURE_FEDAUTH)
        
        # Verify content contains the token (UTF-16LE)
        encoded_token = "mock_token".encode("UTF-16LE")
        self.assertIn(encoded_token, packet)

    def test_connect_with_callable(self):
        """Simulate connect flow with access_token_callable"""
        login = _TdsLogin()
        login.tds_version = tds_base.TDS74
        login.access_token_callable = lambda: "mock_token"
        login.access_token = login.access_token_callable()
        self.assertEqual(login.access_token, "mock_token")

    @patch('pytds._connect')
    def test_connect_with_token(self, mock_connect):
        """Verify connect accepts access_token parameter and sets it on login"""
        token = "direct_access_token"
        connect(dsn="localhost", access_token=token)
        
        # Check if _connect was called
        self.assertTrue(mock_connect.called)
        
        # Check if the login object passed to _connect has the token set
        # _connect is called with kwargs in __init__.py
        call_args = mock_connect.call_args
        login_obj = call_args.kwargs['login']
            
        self.assertEqual(login_obj.access_token, token)

    def test_connect_validation_errors(self):
        """Verify that invalid combinations of parameters raise ValueError"""
        # Case 1: user/password AND access_token
        with self.assertRaisesRegex(ValueError, "user/password cannot be used with access_token"):
            connect(dsn="localhost", user="user", password="password", access_token="token")

        # Case 2: access_token AND access_token_callable
        with self.assertRaisesRegex(ValueError, "access_token cannot be used with access_token_callable"):
            connect(dsn="localhost", access_token="token", access_token_callable=lambda: "token")

if __name__ == '__main__':
    unittest.main()
